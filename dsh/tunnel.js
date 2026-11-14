/**
 * DSH remote tunnel protocol, shared by the Host plugin (as host, and as a device of other DSH
 * hosts) and the browser launcher. The module uses only WebCrypto, WebSocket, Web Streams, EventTarget and TextEncoder,
 * so the same file runs in browsers and in Node 22 or later.
 *
 * Layer 1 speaks the openchamber-relay v1 wire protocol: the host keeps one signed `host-control`
 * socket, opens one signed `host-data` socket per waiting client, and the relay forwards frames
 * between a client socket and its host-data socket without reading them. The relay room is keyed
 * by `serverId`, the SHA-256 of the host's canonical ECDSA P-256 public JWK.
 *
 * Layer 2 is an end-to-end encrypted channel the relay cannot read. The client sends `hello` with
 * an ephemeral ECDH key and its device public key; the host answers `welcome` with its own
 * ephemeral key, its identity key and a signature over the transcript, so a client that knows the
 * `serverId` detects any substitute host. Both sides derive one AES-256-GCM key per direction with
 * HKDF over the ECDH secret, mixing in the one-time pairing secret when pairing. The client then
 * proves its device key by signing the transcript inside the first encrypted frame. Encrypted frames
 * carry no nonce: each direction counts frames, so a dropped, replayed or reordered frame fails
 * authentication and closes the channel.
 *
 * Layer 3 multiplexes HTTP exchanges and WebSocket sessions over one channel, because the relay
 * admits at most 16 concurrent clients and 60 client connections per minute for each host.
 *
 * @module dsh-remote/tunnel
 */

/** Protocol label carried in the handshake and bound into every derived key. */
export const PROTOCOL = 'dsh-remote/1'
/** Largest plaintext payload of one multiplexed frame. */
export const MAX_CHUNK = 64 * 1024

const HIGH_WATER_BYTES = 1024 * 1024
const HANDSHAKE_TIMEOUT_MS = 25_000
const SOCKET_OPEN_TIMEOUT_MS = 15_000
const encoder = new TextEncoder()
const decoder = new TextDecoder()
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGNATURE = { name: 'ECDSA', hash: 'SHA-256' }
const ECDH = { name: 'ECDH', namedCurve: 'P-256' }
const NULL_BODY_STATUS = new Set([101, 103, 204, 205, 304])

function subtle() {
  const value = globalThis.crypto?.subtle
  if (value === undefined) throw new Error('WebCrypto is unavailable; open the page over HTTPS or use Node 22 or later')
  return value
}

/** Failure carrying a stable machine-readable code next to its message. */
export class TunnelError extends Error {
  /**
   * @param {string} code - stable failure code such as `unknown-device`.
   * @param {string} message - human-readable explanation.
   */
  constructor(code, message) {
    super(message)
    this.name = 'TunnelError'
    this.code = code
  }
}

/** Handshake failures after which retrying with the same credentials cannot succeed. */
export const FATAL_CODES = new Set(['unknown-device', 'host-key', 'pairing-invalid', 'protocol'])

// ---------------------------------------------------------------------------
// Bytes and encodings
// ---------------------------------------------------------------------------

/**
 * @param {Uint8Array} bytes - bytes to encode.
 * @returns {string} unpadded base64url text.
 */
export function toBase64Url(bytes) {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * @param {string} text - unpadded base64url text.
 * @returns {Uint8Array} decoded bytes.
 */
export function fromBase64Url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) throw new TunnelError('protocol', 'Malformed base64url value')
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

/**
 * @param {number} [size] - number of random bytes.
 * @returns {string} base64url text of fresh random bytes.
 */
export function randomToken(size = 16) {
  return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(size)))
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.byteLength
  }
  return out
}

/**
 * Normalize socket and stream payloads to a Uint8Array view.
 * @param {ArrayBuffer | ArrayBufferView} data - binary payload.
 * @returns {Uint8Array} view over the same bytes.
 */
export function asBytes(data) {
  if (data instanceof Uint8Array) return data
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  throw new TypeError('Expected binary data')
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms)
    function done() {
      clearTimeout(timer)
      signal?.removeEventListener('abort', done)
      resolve()
    }
    signal?.addEventListener('abort', done, { once: true })
  })
}

// ---------------------------------------------------------------------------
// Signing identities
// ---------------------------------------------------------------------------

/**
 * @param {{ x: string, y: string }} jwk - any P-256 JWK carrying public coordinates.
 * @returns {{ kty: 'EC', crv: 'P-256', x: string, y: string }} the public JWK only.
 */
export function publicJwkOf(jwk) {
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
}

/**
 * Key id used as the relay `serverId` for hosts and as the device id for clients.
 * @param {{ x: string, y: string }} jwk - P-256 public JWK.
 * @returns {Promise<string>} base64url SHA-256 of the canonical public JWK.
 */
export async function keyIdOf(jwk) {
  if (typeof jwk?.x !== 'string' || typeof jwk?.y !== 'string') throw new TunnelError('protocol', 'Malformed public key')
  const canonical = JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })
  return toBase64Url(new Uint8Array(await subtle().digest('SHA-256', encoder.encode(canonical))))
}

/**
 * Create a fresh ECDSA P-256 identity.
 * @param {{ extractable: boolean }} options - whether the private key may be exported for file storage.
 * @returns {Promise<{ id: string, privateKey: CryptoKey, publicJwk: object, privateJwk?: object }>} the identity.
 */
export async function createIdentity({ extractable }) {
  const pair = await subtle().generateKey(ECDSA, extractable, ['sign', 'verify'])
  const publicJwk = publicJwkOf(await subtle().exportKey('jwk', pair.publicKey))
  const identity = { id: await keyIdOf(publicJwk), privateKey: pair.privateKey, publicJwk }
  if (extractable) {
    const exported = await subtle().exportKey('jwk', pair.privateKey)
    identity.privateJwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y, d: exported.d }
  }
  return identity
}

/**
 * Load an identity from a stored private JWK.
 * @param {{ x: string, y: string, d: string }} privateJwk - stored private key.
 * @returns {Promise<{ id: string, privateKey: CryptoKey, publicJwk: object }>} the identity.
 */
export async function importIdentity(privateJwk) {
  const jwk = { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y, d: privateJwk.d }
  const privateKey = await subtle().importKey('jwk', jwk, ECDSA, false, ['sign'])
  const publicJwk = publicJwkOf(jwk)
  return { id: await keyIdOf(publicJwk), privateKey, publicJwk }
}

async function signBytes(privateKey, bytes) {
  return new Uint8Array(await subtle().sign(SIGNATURE, privateKey, bytes))
}

async function verifyBytes(publicJwk, bytes, signature) {
  try {
    const key = await subtle().importKey('jwk', publicJwkOf(publicJwk), ECDSA, false, ['verify'])
    return await subtle().verify(SIGNATURE, key, signature, bytes)
  } catch (_invalidKeyOrSignature) {
    // A malformed key or signature is the same verdict as a wrong signature.
    return false
  }
}

// ---------------------------------------------------------------------------
// Relay addressing and pairing codes
// ---------------------------------------------------------------------------

/**
 * Accept `wss://host/ws`, `https://host`, or a bare host name and return the relay socket URL.
 * @param {string} input - relay address as a user typed it.
 * @returns {string} absolute `ws:` or `wss:` URL; a bare origin gains the `/ws` path.
 */
export function normalizeRelayUrl(input) {
  const text = String(input ?? '').trim()
  if (text === '') throw new TunnelError('config', 'The relay address is empty')
  let url
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `wss://${text}`)
  } catch (_invalid) {
    // URL parsing failures carry no further detail worth keeping.
    throw new TunnelError('config', `Invalid relay address: ${text}`)
  }
  if (url.protocol === 'https:') url.protocol = 'wss:'
  else if (url.protocol === 'http:') url.protocol = 'ws:'
  if (url.protocol !== 'wss:' && url.protocol !== 'ws:') throw new TunnelError('config', `Unsupported relay scheme: ${url.protocol}`)
  if (url.pathname === '/' || url.pathname === '') url.pathname = '/ws'
  url.search = ''
  url.hash = ''
  return url.href
}

/** Most relays a host offers, a pairing code carries, or a device keeps. */
export const MAX_RELAYS = 8

/**
 * Normalize an ordered relay list: invalid entries and duplicates are dropped, order is priority.
 * @param {string | string[] | undefined} input - one address or a list, as typed or stored.
 * @returns {string[]} normalized relay socket URLs, at most {@link MAX_RELAYS}.
 */
export function normalizeRelayList(input) {
  const out = []
  for (const item of Array.isArray(input) ? input : [input]) {
    let url
    try {
      url = normalizeRelayUrl(item)
    } catch (_invalid) {
      // A list skips unusable entries; callers that must report them validate each entry themselves.
      continue
    }
    if (!out.includes(url)) out.push(url)
    if (out.length === MAX_RELAYS) break
  }
  return out
}

function sameList(a, b) {
  return a.length === b.length && a.every((value, index) => value === b[index])
}

/**
 * HTTP origin of a relay socket URL, used for its `/health` probe.
 * @param {string} relayUrl - normalized relay socket URL.
 * @returns {string} health endpoint URL.
 */
export function relayHealthUrl(relayUrl) {
  const url = new URL(relayUrl)
  url.protocol = url.protocol === 'wss:' ? 'https:' : 'http:'
  url.pathname = '/health'
  return url.href
}

/**
 * Signed socket URL for a host role.
 * @param {string} relayUrl - normalized relay socket URL.
 * @param {{ id: string, privateKey: CryptoKey, publicJwk: object }} identity - host identity.
 * @param {'host-control' | 'host-data'} role - relay role.
 * @param {string} [connectionId] - client connection served by a host-data socket.
 * @returns {Promise<string>} URL carrying `ts`, `sig` and `pk`.
 */
export async function hostSocketUrl(relayUrl, identity, role, connectionId) {
  const ts = String(Date.now())
  const signature = await signBytes(identity.privateKey, encoder.encode(`${ts}.${identity.id}.${role}.${connectionId ?? ''}`))
  const url = new URL(relayUrl)
  url.searchParams.set('v', '1')
  url.searchParams.set('role', role)
  url.searchParams.set('serverId', identity.id)
  if (connectionId !== undefined) url.searchParams.set('connectionId', connectionId)
  url.searchParams.set('ts', ts)
  url.searchParams.set('sig', toBase64Url(signature))
  url.searchParams.set('pk', toBase64Url(encoder.encode(JSON.stringify(identity.publicJwk))))
  return url.href
}

/**
 * @param {string} relayUrl - normalized relay socket URL.
 * @param {string} serverId - host key id.
 * @param {string} connectionId - fresh random id for this client socket.
 * @returns {string} client socket URL.
 */
export function clientSocketUrl(relayUrl, serverId, connectionId) {
  const url = new URL(relayUrl)
  url.searchParams.set('v', '1')
  url.searchParams.set('role', 'client')
  url.searchParams.set('serverId', serverId)
  url.searchParams.set('connectionId', connectionId)
  return url.href
}

function compactRelay(relayUrl) {
  const url = new URL(relayUrl)
  return url.protocol === 'wss:' && url.pathname === '/ws' ? url.host : relayUrl
}

/**
 * Encode a one-time pairing offer as URL-fragment text. Each relay is one `r` parameter, in priority
 * order; decoders that predate relay lists read the first one.
 * @param {{ relayUrls: string[], serverId: string, pairingId: string, secret: string, hostName: string, expiresAt: number }} offer - pairing offer.
 * @returns {string} code usable as a URL fragment, in a launcher link or a `dsh-remote://pair#…` link.
 */
export function encodePairing(offer) {
  const params = new URLSearchParams()
  for (const relayUrl of normalizeRelayList(offer.relayUrls ?? offer.relayUrl)) params.append('r', compactRelay(relayUrl))
  params.set('s', offer.serverId)
  params.set('i', offer.pairingId)
  params.set('k', offer.secret)
  params.set('e', Math.floor(offer.expiresAt / 1000).toString(36))
  params.set('n', offer.hostName)
  return params.toString()
}

/**
 * Decode a pairing code, a launcher link, or a link fragment.
 * @param {string} input - code or link.
 * @returns {{ relayUrls: string[], relayUrl: string, serverId: string, pairingId: string, secret: string, hostName: string, expiresAt: number }} the offer; `relayUrl` is the first relay.
 */
export function decodePairing(input) {
  let text = String(input ?? '').trim()
  const hash = text.indexOf('#')
  if (hash >= 0) text = text.slice(hash + 1)
  const params = new URLSearchParams(text)
  const field = (name) => {
    const value = params.get(name)
    if (value === null || value === '') throw new TunnelError('pairing-invalid', 'This is not a complete DSH pairing code')
    return value
  }
  const serverId = field('s')
  const pairingId = field('i')
  const secret = field('k')
  if (!/^[A-Za-z0-9_-]{43}$/.test(serverId) || !/^[A-Za-z0-9_-]{8,64}$/.test(pairingId) || fromBase64Url(secret).length < 16) {
    throw new TunnelError('pairing-invalid', 'This pairing code is malformed')
  }
  const expiresAt = Number.parseInt(field('e'), 36) * 1000
  const relayUrls = normalizeRelayList(params.getAll('r'))
  // With no usable entry, report why the first one is unusable.
  if (relayUrls.length === 0) normalizeRelayUrl(field('r'))
  return {
    relayUrls,
    relayUrl: relayUrls[0],
    serverId,
    pairingId,
    secret,
    hostName: (params.get('n') ?? '').slice(0, 80),
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : 0,
  }
}

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

/**
 * Open a WebSocket and wait until it is usable.
 * @param {string} url - socket URL.
 * @param {number} [timeoutMs] - open deadline.
 * @returns {Promise<WebSocket>} an open socket delivering binary frames as ArrayBuffer.
 */
export function openSocket(url, timeoutMs = SOCKET_OPEN_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url)
    ws.binaryType = 'arraybuffer'
    const timer = setTimeout(() => {
      cleanup()
      try { ws.close() } catch (_alreadyClosing) { /* closing an unopened socket can throw; the deadline already decided */ }
      reject(new TunnelError('relay-timeout', 'The relay did not answer in time'))
    }, timeoutMs)
    const onOpen = () => { cleanup(); resolve(ws) }
    const onClose = (event) => {
      cleanup()
      reject(new TunnelError('relay-closed', `The relay refused the connection (${event.code}${event.reason ? `: ${event.reason}` : ''})`))
    }
    function cleanup() {
      clearTimeout(timer)
      ws.removeEventListener('open', onOpen)
      ws.removeEventListener('close', onClose)
    }
    ws.addEventListener('open', onOpen)
    ws.addEventListener('close', onClose)
  })
}

/** Buffers socket messages until the handshake or the encrypted channel consumes them. */
class Inbox {
  constructor(ws) {
    this.items = []
    this.waiters = []
    this.closed = undefined
    this.sink = undefined
    this.onClosed = undefined
    ws.addEventListener('message', (event) => { this.push(event.data) })
    ws.addEventListener('close', (event) => { this.close(event.code, event.reason) })
  }

  push(data) {
    if (this.sink !== undefined) {
      this.sink(data)
      return
    }
    const waiter = this.waiters.shift()
    if (waiter !== undefined) waiter.resolve(data)
    else this.items.push(data)
  }

  close(code, reason) {
    if (this.closed !== undefined) return
    this.closed = { code, reason }
    for (const waiter of this.waiters.splice(0)) {
      waiter.reject(new TunnelError('closed', `Connection closed (${code}${reason ? `: ${reason}` : ''})`))
    }
    this.onClosed?.(code, reason)
  }

  next(timeoutMs) {
    if (this.items.length > 0) return Promise.resolve(this.items.shift())
    if (this.closed !== undefined) {
      return Promise.reject(new TunnelError('closed', `Connection closed (${this.closed.code})`))
    }
    return new Promise((resolve, reject) => {
      const waiter = {
        resolve: (value) => { clearTimeout(timer); resolve(value) },
        reject: (error) => { clearTimeout(timer); reject(error) },
      }
      const timer = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(waiter), 1)
        reject(new TunnelError('timeout', 'The other side did not answer in time'))
      }, timeoutMs)
      this.waiters.push(waiter)
    })
  }

  forward(sink, onClosed) {
    this.sink = sink
    this.onClosed = onClosed
    for (const item of this.items.splice(0)) sink(item)
    if (this.closed !== undefined) onClosed(this.closed.code, this.closed.reason)
  }
}

function closeSocket(ws, code, reason) {
  try {
    ws.close(code, reason)
  } catch (_invalidState) {
    // The socket is already closing; the close event reports the outcome.
  }
}

// ---------------------------------------------------------------------------
// Encrypted channel
// ---------------------------------------------------------------------------

function nonceOf(counter) {
  const iv = new Uint8Array(12)
  const view = new DataView(iv.buffer)
  view.setUint32(4, Math.floor(counter / 0x100000000))
  view.setUint32(8, counter >>> 0)
  return iv
}

/** AES-256-GCM frames over one socket, one key and one implicit counter per direction. */
export class SecureChannel {
  constructor(ws, inbox, sendKey, receiveKey) {
    this.ws = ws
    this.sendKey = sendKey
    this.receiveKey = receiveKey
    this.sendCounter = 0
    this.receiveCounter = 0
    this.sendTail = Promise.resolve()
    this.receiveTail = Promise.resolve()
    this.pendingBytes = 0
    this.closed = false
    this.queue = []
    this.waiter = undefined
    this.handler = undefined
    /** @type {((code: number, reason: string) => void) | undefined} */
    this.onclose = undefined
    inbox.forward((data) => { this.receive(data) }, (code, reason) => { this.terminate(code, reason) })
  }

  /** Bytes accepted by {@link send} that the socket has not yet transmitted. */
  get bufferedAmount() {
    return this.pendingBytes + (this.ws.bufferedAmount ?? 0)
  }

  /**
   * Queue one plaintext frame; frames leave in call order.
   * @param {Uint8Array} bytes - plaintext.
   * @returns {Promise<void>} settles once the ciphertext was handed to the socket.
   */
  send(bytes) {
    if (this.closed) return Promise.reject(new TunnelError('closed', 'The tunnel is closed'))
    const counter = this.sendCounter
    this.sendCounter += 1
    this.pendingBytes += bytes.byteLength
    const task = this.sendTail.then(async () => {
      const sealed = await subtle().encrypt({ name: 'AES-GCM', iv: nonceOf(counter) }, this.sendKey, bytes)
      this.pendingBytes -= bytes.byteLength
      if (!this.closed) this.ws.send(sealed)
    })
    this.sendTail = task.catch(() => {})
    return task
  }

  /** Wait until queued output falls below the high-water mark. */
  async drain() {
    while (!this.closed && this.bufferedAmount > HIGH_WATER_BYTES) await sleep(10)
  }

  /**
   * Install the frame consumer and deliver frames buffered before it existed.
   * @param {(bytes: Uint8Array) => void} handler - receives each decrypted frame in order.
   */
  setHandler(handler) {
    this.handler = handler
    for (const frame of this.queue.splice(0)) handler(frame)
  }

  /**
   * Take the next decrypted frame before a handler is installed.
   * @param {number} timeoutMs - deadline.
   * @returns {Promise<Uint8Array>} frame.
   */
  nextFrame(timeoutMs) {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift())
    if (this.closed) return Promise.reject(new TunnelError('closed', 'The tunnel is closed'))
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = undefined
        reject(new TunnelError('timeout', 'The other side did not answer in time'))
      }, timeoutMs)
      this.waiter = {
        resolve: (value) => { clearTimeout(timer); resolve(value) },
        reject: (error) => { clearTimeout(timer); reject(error) },
      }
    })
  }

  receive(data) {
    if (typeof data === 'string') {
      this.close(4400, 'unexpected text frame')
      return
    }
    const counter = this.receiveCounter
    this.receiveCounter += 1
    const sealed = asBytes(data)
    this.receiveTail = this.receiveTail.then(async () => {
      if (this.closed) return
      let plain
      try {
        plain = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonceOf(counter) }, this.receiveKey, sealed))
      } catch (_authenticationFailure) {
        // A frame that fails authentication means tampering, loss or the wrong key: stop at once.
        this.close(4400, 'frame authentication failed')
        return
      }
      try {
        this.deliver(plain)
      } catch (error) {
        // A consumer that cannot parse a frame leaves the stream state unknown: end the channel.
        console.error('[dsh-remote] frame handler failed:', error)
        this.close(4400, 'protocol error')
      }
    })
  }

  deliver(plain) {
    if (this.waiter !== undefined) {
      const waiter = this.waiter
      this.waiter = undefined
      waiter.resolve(plain)
    } else if (this.handler !== undefined) {
      this.handler(plain)
    } else {
      this.queue.push(plain)
    }
  }

  /**
   * Close the socket and report the closure once.
   * @param {number} [code] - WebSocket close code (1000 or 3000-4999).
   * @param {string} [reason] - short reason.
   */
  close(code = 1000, reason = '') {
    if (this.closed) return
    closeSocket(this.ws, code, reason)
    this.terminate(code, reason)
  }

  terminate(code, reason) {
    if (this.closed) return
    this.closed = true
    this.waiter?.reject(new TunnelError('closed', `Connection closed (${code}${reason ? `: ${reason}` : ''})`))
    this.waiter = undefined
    this.onclose?.(code, reason)
  }
}

async function ephemeralKey() {
  const pair = await subtle().generateKey(ECDH, false, ['deriveBits'])
  const raw = new Uint8Array(await subtle().exportKey('raw', pair.publicKey))
  return { privateKey: pair.privateKey, publicText: toBase64Url(raw) }
}

async function transcriptOf(helloText, hostEphemeral) {
  return new Uint8Array(await subtle().digest('SHA-256', encoder.encode(`${PROTOCOL}\n${helloText}\n${hostEphemeral}`)))
}

async function deriveKeys(privateKey, peerPublicText, transcript, preShared) {
  const peer = await subtle().importKey('raw', fromBase64Url(peerPublicText), ECDH, false, [])
  const shared = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: peer }, privateKey, 256))
  const material = await subtle().importKey('raw', concatBytes(shared, preShared ?? new Uint8Array(0)), 'HKDF', false, ['deriveBits'])
  const bits = new Uint8Array(await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: transcript, info: encoder.encode(`${PROTOCOL} channel keys`) },
    material,
    512,
  ))
  const importKey = (bytes) => subtle().importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt'])
  return { clientToHost: await importKey(bits.slice(0, 32)), hostToClient: await importKey(bits.slice(32)) }
}

function parseJson(text, what) {
  try {
    const value = JSON.parse(text)
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) return value
  } catch (_syntax) {
    // Reported below as a protocol failure naming the message.
  }
  throw new TunnelError('protocol', `Malformed ${what}`)
}

function isPublicJwk(value) {
  return typeof value === 'object' && value !== null && typeof value.x === 'string' && typeof value.y === 'string'
}

/**
 * Connect to a host through the relay and complete the client handshake.
 * @param {object} options - connection options.
 * @param {string} options.relayUrl - normalized relay socket URL.
 * @param {string} options.serverId - expected host key id.
 * @param {{ privateKey: CryptoKey, publicJwk: object }} options.device - device identity.
 * @param {string} options.deviceName - name the host shows for this device.
 * @param {'pair' | 'auth'} options.mode - pair with a one-time code, or authenticate a paired device.
 * @param {{ pairingId: string, secret: string }} [options.pairing] - required for `pair`.
 * @param {boolean} [options.probe] - a short-lived latency probe, which the host does not log as a visit.
 * @param {AbortSignal} [options.signal] - abandons the attempt and closes its socket.
 * @returns {Promise<{ channel: SecureChannel, hostName: string, device: { id: string, name: string }, relays?: string[] }>} the ready channel, and the relays the host offers now when it says so.
 */
export async function connectClient({ relayUrl, serverId, device, deviceName, mode, pairing, probe, signal }) {
  signal?.throwIfAborted()
  const ws = await openSocket(clientSocketUrl(relayUrl, serverId, randomToken(16)))
  const inbox = new Inbox(ws)
  const cancel = () => { closeSocket(ws, 1000, 'cancelled') }
  signal?.addEventListener('abort', cancel, { once: true })
  try {
    const ephemeral = await ephemeralKey()
    const helloText = JSON.stringify({
      t: 'hello',
      p: PROTOCOL,
      e: ephemeral.publicText,
      m: mode,
      d: publicJwkOf(device.publicJwk),
      ...mode === 'pair' ? { i: pairing.pairingId } : {},
    })
    ws.send(helloText)
    const first = await inbox.next(HANDSHAKE_TIMEOUT_MS)
    if (typeof first !== 'string') throw new TunnelError('protocol', 'The host answered with an unexpected frame')
    const welcome = parseJson(first, 'welcome')
    if (welcome.t === 'error') throw new TunnelError(String(welcome.c ?? 'refused'), String(welcome.r ?? 'The host refused the connection'))
    if (welcome.t !== 'welcome' || welcome.p !== PROTOCOL || typeof welcome.e !== 'string' || !isPublicJwk(welcome.k)) {
      throw new TunnelError('protocol', 'The host speaks an incompatible protocol')
    }
    if (await keyIdOf(welcome.k) !== serverId) throw new TunnelError('host-key', 'The answering host is not the paired DSH')
    const transcript = await transcriptOf(helloText, welcome.e)
    if (!await verifyBytes(welcome.k, transcript, fromBase64Url(String(welcome.s)))) {
      throw new TunnelError('host-key', 'The host signature is invalid')
    }
    const keys = await deriveKeys(ephemeral.privateKey, welcome.e, transcript, mode === 'pair' ? fromBase64Url(pairing.secret) : undefined)
    const channel = new SecureChannel(ws, inbox, keys.clientToHost, keys.hostToClient)
    const proof = await signBytes(device.privateKey, transcript)
    const answer = channel.nextFrame(HANDSHAKE_TIMEOUT_MS)
    await channel.send(encoder.encode(JSON.stringify({ t: 'auth', s: toBase64Url(proof), n: String(deviceName ?? '').slice(0, 80), ...probe ? { q: 1 } : {} })))
    let reply
    try {
      reply = parseJson(decoder.decode(await answer), 'host reply')
    } catch (error) {
      if (mode === 'pair' && error instanceof TunnelError && error.code === 'closed') {
        throw new TunnelError('pairing-invalid', 'The host rejected this pairing code')
      }
      throw error
    }
    if (reply.t !== 'ready') {
      channel.close(1000, 'denied')
      throw new TunnelError(String(reply.c ?? 'denied'), String(reply.r ?? 'The host refused this device'))
    }
    const relays = Array.isArray(reply.r) ? normalizeRelayList(reply.r.slice(0, MAX_RELAYS)) : []
    return {
      channel,
      hostName: String(reply.h ?? ''),
      device: { id: String(reply.d?.id ?? ''), name: String(reply.d?.name ?? '') },
      ...relays.length > 0 ? { relays } : {},
    }
  } catch (error) {
    closeSocket(ws, 4000, 'handshake failed')
    throw error
  } finally {
    signal?.removeEventListener('abort', cancel)
  }
}

/**
 * Complete the host side of the handshake on an open host-data socket.
 * @param {WebSocket} ws - open host-data socket.
 * @param {object} options - handshake policy.
 * @param {{ privateKey: CryptoKey, publicJwk: object }} options.identity - host identity.
 * @param {string} options.hostName - name reported to the device.
 * @param {(pairingId: string) => Uint8Array | undefined} options.pairingSecret - secret of a live pairing offer.
 * @param {(request: { mode: 'pair' | 'auth', pairingId?: string, deviceId: string, deviceKey: object, deviceName: string }) => Promise<{ ok: true, device: { id: string, name: string } } | { ok: false, code: string, reason: string }>} options.authorize - admission decision after both keys are verified.
 * @param {string[]} [options.relays] - relays the host offers now, in priority order; the device keeps this list.
 * @returns {Promise<{ channel: SecureChannel, device: { id: string, name: string }, probe: boolean }>} the ready channel, and whether the device only measures latency.
 */
export async function acceptHost(ws, { identity, hostName, pairingSecret, authorize, relays }) {
  const inbox = new Inbox(ws)
  try {
    const helloText = await inbox.next(HANDSHAKE_TIMEOUT_MS)
    if (typeof helloText !== 'string') throw new TunnelError('protocol', 'Expected a text hello')
    const hello = parseJson(helloText, 'hello')
    if (hello.t !== 'hello' || hello.p !== PROTOCOL || typeof hello.e !== 'string' || !isPublicJwk(hello.d)
      || (hello.m !== 'pair' && hello.m !== 'auth') || (hello.m === 'pair' && typeof hello.i !== 'string')) {
      ws.send(JSON.stringify({ t: 'error', c: 'protocol', r: 'Incompatible DSH remote protocol' }))
      throw new TunnelError('protocol', 'Malformed hello')
    }
    let preShared
    if (hello.m === 'pair') {
      preShared = pairingSecret(hello.i)
      if (preShared === undefined) {
        ws.send(JSON.stringify({ t: 'error', c: 'pairing-invalid', r: 'This pairing code is invalid, used, or expired' }))
        throw new TunnelError('pairing-invalid', 'Unknown pairing')
      }
    }
    const ephemeral = await ephemeralKey()
    const transcript = await transcriptOf(helloText, ephemeral.publicText)
    const signature = await signBytes(identity.privateKey, transcript)
    ws.send(JSON.stringify({ t: 'welcome', p: PROTOCOL, e: ephemeral.publicText, k: identity.publicJwk, s: toBase64Url(signature) }))
    const keys = await deriveKeys(ephemeral.privateKey, hello.e, transcript, preShared)
    const channel = new SecureChannel(ws, inbox, keys.hostToClient, keys.clientToHost)
    const auth = parseJson(decoder.decode(await channel.nextFrame(HANDSHAKE_TIMEOUT_MS)), 'auth')
    if (auth.t !== 'auth' || !await verifyBytes(hello.d, transcript, fromBase64Url(String(auth.s)))) {
      channel.close(4401, 'device proof invalid')
      throw new TunnelError('protocol', 'Device proof invalid')
    }
    const verdict = await authorize({
      mode: hello.m,
      ...hello.m === 'pair' ? { pairingId: hello.i } : {},
      deviceId: await keyIdOf(hello.d),
      deviceKey: publicJwkOf(hello.d),
      deviceName: String(auth.n ?? '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, 80),
    })
    if (!verdict.ok) {
      await channel.send(encoder.encode(JSON.stringify({ t: 'denied', c: verdict.code, r: verdict.reason })))
      setTimeout(() => { channel.close(4403, 'denied') }, 200)
      throw new TunnelError(verdict.code, verdict.reason)
    }
    const offered = normalizeRelayList(relays ?? [])
    await channel.send(encoder.encode(JSON.stringify({ t: 'ready', h: hostName, d: verdict.device, ...offered.length > 0 ? { r: offered } : {} })))
    return { channel, device: verdict.device, probe: auth.q === 1 }
  } catch (error) {
    closeSocket(ws, 4000, 'handshake failed')
    throw error
  }
}

// ---------------------------------------------------------------------------
// Multiplexer
// ---------------------------------------------------------------------------

const FRAME = Object.freeze({
  REQUEST: 1,
  RESPONSE: 2,
  DATA: 3,
  END: 4,
  RESET: 5,
  WS_OPEN: 6,
  WS_ACCEPT: 7,
  WS_TEXT: 8,
  WS_BINARY: 9,
  WS_CLOSE: 10,
  PING: 11,
  PONG: 12,
  WS_FRAGMENT: 13,
})

function encodeFrame(type, id, payload) {
  const body = payload === undefined ? new Uint8Array(0) : typeof payload === 'string' ? encoder.encode(payload) : payload
  const out = new Uint8Array(5 + body.byteLength)
  out[0] = type
  new DataView(out.buffer).setUint32(1, id)
  out.set(body, 5)
  return out
}

/**
 * Convert any header container to `[name, value]` pairs with lower-case names.
 * @param {Headers | Iterable<[string, string]> | Record<string, string | string[] | undefined>} input - headers.
 * @returns {Array<[string, string]>} pairs.
 */
export function headerPairs(input) {
  const out = []
  if (input === undefined || input === null) return out
  if (typeof input[Symbol.iterator] === 'function') {
    for (const [name, value] of input) out.push([String(name).toLowerCase(), String(value)])
    return out
  }
  for (const [name, value] of Object.entries(input)) {
    if (value === undefined) continue
    for (const item of Array.isArray(value) ? value : [value]) out.push([name.toLowerCase(), String(item)])
  }
  return out
}

async function* iterateBody(body) {
  if (body === undefined || body === null) return
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    yield asBytes(body)
    return
  }
  if (typeof body.getReader === 'function') {
    const reader = body.getReader()
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) return
        yield asBytes(value)
      }
    } finally {
      reader.releaseLock()
    }
  }
  for await (const chunk of body) yield typeof chunk === 'string' ? encoder.encode(chunk) : asBytes(chunk)
}

function splitBytes(bytes) {
  if (bytes.byteLength <= MAX_CHUNK) return [bytes]
  const parts = []
  for (let offset = 0; offset < bytes.byteLength; offset += MAX_CHUNK) parts.push(bytes.subarray(offset, offset + MAX_CHUNK))
  return parts
}

function closeEvent(code, reason, wasClean) {
  if (typeof CloseEvent === 'function') return new CloseEvent('close', { code, reason, wasClean })
  const event = new Event('close')
  Object.defineProperties(event, { code: { value: code }, reason: { value: reason }, wasClean: { value: wasClean } })
  return event
}

/**
 * WebSocket-compatible object whose traffic travels through the tunnel. It implements the subset
 * of the WebSocket API that browsers and the DSH Web GUI use: `readyState`, `send`, `close`,
 * `binaryType`, `protocol`, the four `on*` handler properties and `addEventListener`.
 */
export class TunnelSocket extends EventTarget {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  /** @param {string} url - URL the page asked for, reported back through `url`. */
  constructor(url) {
    super()
    this.url = url
    this.readyState = 0
    this.protocol = ''
    this.extensions = ''
    this.binaryType = 'blob'
    this.onopen = null
    this.onmessage = null
    this.onclose = null
    this.onerror = null
    this.transport = undefined
  }

  get CONNECTING() { return 0 }
  get OPEN() { return 1 }
  get CLOSING() { return 2 }
  get CLOSED() { return 3 }
  get bufferedAmount() { return this.transport?.bufferedAmount() ?? 0 }

  /** @param {string | ArrayBuffer | ArrayBufferView | Blob} data - message. */
  send(data) {
    if (this.readyState === 0) throw new DOMException('WebSocket is still connecting', 'InvalidStateError')
    if (this.readyState !== 1) return
    if (typeof data === 'string') this.transport.send(encoder.encode(data), true)
    else if (typeof Blob !== 'undefined' && data instanceof Blob) {
      void data.arrayBuffer().then((buffer) => { if (this.readyState === 1) this.transport.send(new Uint8Array(buffer), false) })
    } else this.transport.send(asBytes(data), false)
  }

  /**
   * @param {number} [code] - close code.
   * @param {string} [reason] - close reason.
   */
  close(code = 1000, reason = '') {
    if (this.readyState >= 2) return
    if (this.transport === undefined) {
      this.finish(code, reason, false)
      return
    }
    this.readyState = 2
    this.transport.close(code, reason)
  }

  emit(type, event) {
    this.dispatchEvent(event)
    const handler = this[`on${type}`]
    if (typeof handler === 'function') handler.call(this, event)
  }

  opened(protocol) {
    if (this.readyState !== 0) return
    this.readyState = 1
    this.protocol = protocol
    this.emit('open', new Event('open'))
  }

  message(bytes, isText) {
    if (this.readyState !== 1) return
    let data
    if (isText) data = decoder.decode(bytes)
    else if (this.binaryType === 'arraybuffer') data = bytes.slice().buffer
    else data = new Blob([bytes])
    this.emit('message', new MessageEvent('message', { data }))
  }

  fail(code = 1006, reason = '') {
    if (this.readyState === 3) return
    this.emit('error', new Event('error'))
    this.finish(code, reason, false)
  }

  finish(code, reason, wasClean) {
    if (this.readyState === 3) return
    this.readyState = 3
    this.emit('close', closeEvent(code, reason, wasClean))
  }
}

/**
 * Stream multiplexer over one {@link SecureChannel}. The client side calls {@link Mux#request} and
 * {@link Mux#attachWebSocket}; the host side supplies `request` and `websocket` handlers.
 */
export class Mux {
  /**
   * @param {SecureChannel} channel - ready encrypted channel.
   * @param {object} [options] - handlers and keep-alive timing.
   * @param {(exchange: object) => void | Promise<void>} [options.request] - host handler for HTTP exchanges.
   * @param {(session: object) => void | Promise<void>} [options.websocket] - host handler for WebSocket sessions.
   * @param {number} [options.keepAliveMs] - ping interval; three silent intervals close the channel.
   *   Every keep-alive ping also measures the round trip, see {@link Mux#rtt}.
   */
  constructor(channel, options = {}) {
    this.channel = channel
    this.handlers = options
    this.streams = new Map()
    this.nextId = 1
    this.closed = false
    this.lastSeen = Date.now()
    /** @type {((code: number, reason: string) => void) | undefined} */
    this.onclose = undefined
    this.pings = []
    this.nextPing = 1
    /** Latest end-to-end round trip in milliseconds, through the relay to the other end; null until measured. */
    this.rtt = null
    channel.onclose = (code, reason) => { this.shutdown(code, reason) }
    channel.setHandler((bytes) => { this.receive(bytes) })
    const keepAliveMs = options.keepAliveMs ?? 25_000
    const measure = () => { this.ping(keepAliveMs).catch(() => {}) }
    this.keepAlive = setInterval(() => {
      if (Date.now() - this.lastSeen > keepAliveMs * 3) {
        channel.close(4408, 'keep-alive timeout')
        return
      }
      measure()
    }, keepAliveMs)
    // A first measurement right away, so a new tunnel reports its latency without waiting an interval.
    setTimeout(measure, 0)
  }

  /** Close the channel and fail every open stream. */
  close() {
    this.channel.close(1000, 'closed')
  }

  /**
   * Measure one round trip through the relay to the other end.
   * @param {number} [timeoutMs] - deadline.
   * @returns {Promise<number>} round-trip time in milliseconds.
   */
  ping(timeoutMs = 10_000) {
    if (this.closed) return Promise.reject(new TunnelError('closed', 'The tunnel is closed'))
    const id = this.nextPing
    this.nextPing = this.nextPing >= 0x7fffffff ? 1 : this.nextPing + 1
    return new Promise((resolve, reject) => {
      const started = performance.now()
      const waiter = {
        id,
        done: (error) => {
          clearTimeout(timer)
          this.pings = this.pings.filter((candidate) => candidate !== waiter)
          if (error !== undefined) {
            reject(error)
            return
          }
          this.rtt = Math.round(performance.now() - started)
          resolve(this.rtt)
        },
      }
      const timer = setTimeout(() => { waiter.done(new TunnelError('timeout', 'No answer in time')) }, timeoutMs)
      this.pings.push(waiter)
      this.send(FRAME.PING, id)
    })
  }

  send(type, id, payload) {
    return this.channel.send(encodeFrame(type, id, payload)).catch(() => {})
  }

  sendJson(type, id, value) {
    return this.send(type, id, JSON.stringify(value))
  }

  async writeData(id, stream, bytes) {
    for (const part of splitBytes(bytes)) {
      await this.channel.drain()
      if (this.streams.get(id) !== stream) return
      await this.send(FRAME.DATA, id, part)
    }
  }

  sendMessage(id, bytes, isText) {
    const parts = splitBytes(bytes)
    for (let i = 0; i < parts.length - 1; i += 1) this.send(FRAME.WS_FRAGMENT, id, parts[i])
    this.send(isText ? FRAME.WS_TEXT : FRAME.WS_BINARY, id, parts[parts.length - 1])
  }

  allocate() {
    const id = this.nextId
    this.nextId += 2
    return id
  }

  /**
   * Perform one HTTP exchange on the host.
   * @param {{ method: string, path: string, headers?: Array<[string, string]>, body?: BodyInit | AsyncIterable<Uint8Array> | null }} init - request.
   * @param {AbortSignal} [signal] - cancellation.
   * @returns {Promise<{ status: number, statusText: string, headers: Array<[string, string]>, body: ReadableStream<Uint8Array> | null }>} response.
   */
  request(init, signal) {
    if (this.closed) return Promise.reject(new TunnelError('closed', 'The tunnel is closed'))
    signal?.throwIfAborted()
    const id = this.allocate()
    return new Promise((resolve, reject) => {
      const stream = { kind: 'request', resolve, reject, controller: undefined, answered: false, cleanup: () => {} }
      const abort = () => {
        if (this.streams.get(id) !== stream) return
        this.send(FRAME.RESET, id)
        this.failStream(id, stream, signal.reason ?? new DOMException('Aborted', 'AbortError'))
      }
      if (signal !== undefined) {
        signal.addEventListener('abort', abort, { once: true })
        stream.cleanup = () => { signal.removeEventListener('abort', abort) }
      }
      this.streams.set(id, stream)
      this.sendJson(FRAME.REQUEST, id, { m: init.method, p: init.path, h: headerPairs(init.headers) })
      void this.pumpBody(id, stream, init.body)
    })
  }

  async pumpBody(id, stream, body) {
    try {
      for await (const chunk of iterateBody(body)) {
        if (this.streams.get(id) !== stream) return
        await this.writeData(id, stream, chunk)
      }
      if (this.streams.get(id) === stream) this.send(FRAME.END, id)
    } catch (error) {
      if (this.streams.get(id) !== stream) return
      this.sendJson(FRAME.RESET, id, { e: String(error?.message ?? error) })
      this.failStream(id, stream, error)
    }
  }

  /**
   * Bind a {@link TunnelSocket} to a WebSocket on the host.
   * @param {TunnelSocket} socket - socket in CONNECTING state.
   * @param {string} path - host path and query.
   * @param {{ protocols?: string[], headers?: Array<[string, string]> }} [options] - subprotocols and extra headers.
   */
  attachWebSocket(socket, path, options = {}) {
    if (socket.readyState !== 0) return
    if (this.closed) {
      socket.fail()
      return
    }
    const id = this.allocate()
    const stream = { kind: 'socket', socket, fragments: [] }
    this.streams.set(id, stream)
    socket.transport = {
      send: (bytes, isText) => { if (this.streams.get(id) === stream) this.sendMessage(id, bytes, isText) },
      close: (code, reason) => {
        if (this.streams.get(id) !== stream) return
        this.sendJson(FRAME.WS_CLOSE, id, { c: code, r: reason })
        setTimeout(() => {
          if (this.streams.get(id) !== stream) return
          this.streams.delete(id)
          socket.finish(code, reason, true)
        }, 3000)
      },
      bufferedAmount: () => this.channel.bufferedAmount,
    }
    this.sendJson(FRAME.WS_OPEN, id, { p: path, s: options.protocols ?? [], h: headerPairs(options.headers) })
  }

  failStream(id, stream, error) {
    this.streams.delete(id)
    if (stream.kind === 'request') {
      stream.cleanup()
      if (!stream.answered) stream.reject(error)
      else stream.controller?.error(error)
    } else if (stream.kind === 'socket') {
      stream.socket.fail(1006, String(error?.message ?? ''))
    } else if (stream.kind === 'exchange') {
      stream.abort.abort(error)
      try { stream.bodyController?.error(error) } catch (_closed) { /* the request body already ended */ }
    } else if (stream.kind === 'session') {
      stream.notifyClose(1006, '')
    }
  }

  receive(bytes) {
    this.lastSeen = Date.now()
    if (bytes.byteLength < 5) return
    const type = bytes[0]
    const id = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(1)
    const payload = bytes.subarray(5)
    if (type === FRAME.PING) {
      this.send(FRAME.PONG, id)
      return
    }
    if (type === FRAME.PONG) {
      // Hosts before relay lists answer every ping with id 0; take the oldest waiter then.
      const waiter = id === 0 ? this.pings[0] : this.pings.find((candidate) => candidate.id === id)
      waiter?.done()
      return
    }
    if (type === FRAME.REQUEST) {
      this.acceptExchange(id, payload)
      return
    }
    if (type === FRAME.WS_OPEN) {
      this.acceptSession(id, payload)
      return
    }
    const stream = this.streams.get(id)
    if (stream === undefined) return
    switch (stream.kind) {
      case 'request': this.receiveResponse(id, stream, type, payload); break
      case 'socket': this.receiveSocket(id, stream, type, payload); break
      case 'exchange': this.receiveExchange(id, stream, type, payload); break
      case 'session': this.receiveSession(id, stream, type, payload); break
      default: break
    }
  }

  receiveResponse(id, stream, type, payload) {
    if (type === FRAME.RESPONSE && !stream.answered) {
      const head = parseJson(decoder.decode(payload), 'response head')
      stream.answered = true
      const status = Number(head.s)
      const body = NULL_BODY_STATUS.has(status) ? null : new ReadableStream({
        start: (controller) => { stream.controller = controller },
        cancel: () => {
          if (this.streams.get(id) !== stream) return
          this.streams.delete(id)
          stream.cleanup()
          this.send(FRAME.RESET, id)
        },
      }, { highWaterMark: 0 })
      stream.resolve({ status, statusText: String(head.st ?? ''), headers: Array.isArray(head.h) ? head.h : [], body })
    } else if (type === FRAME.DATA) {
      stream.controller?.enqueue(payload)
    } else if (type === FRAME.END) {
      this.streams.delete(id)
      stream.cleanup()
      if (!stream.answered) stream.reject(new TunnelError('protocol', 'The host ended the exchange without a response'))
      else try { stream.controller?.close() } catch (_cancelled) { /* the reader cancelled first */ }
    } else if (type === FRAME.RESET) {
      const message = payload.byteLength > 0 ? String(parseJson(decoder.decode(payload), 'reset').e ?? 'reset') : 'The host reset the exchange'
      this.failStream(id, stream, new TunnelError('reset', message))
    }
  }

  receiveSocket(id, stream, type, payload) {
    const { socket } = stream
    if (type === FRAME.WS_ACCEPT) {
      socket.opened(String(parseJson(decoder.decode(payload), 'accept').s ?? ''))
    } else if (type === FRAME.WS_FRAGMENT) {
      stream.fragments.push(payload.slice())
    } else if (type === FRAME.WS_TEXT || type === FRAME.WS_BINARY) {
      const whole = stream.fragments.length === 0 ? payload : concatBytes(...stream.fragments.splice(0), payload)
      socket.message(whole, type === FRAME.WS_TEXT)
    } else if (type === FRAME.WS_CLOSE) {
      const info = parseJson(decoder.decode(payload), 'close')
      this.streams.delete(id)
      if (socket.readyState === 0) socket.fail(Number(info.c) || 1006, String(info.r ?? ''))
      else socket.finish(Number(info.c) || 1005, String(info.r ?? ''), true)
    } else if (type === FRAME.RESET) {
      this.failStream(id, stream, new TunnelError('reset', 'The host reset the socket'))
    }
  }

  acceptExchange(id, payload) {
    if (this.handlers.request === undefined || this.streams.has(id)) {
      this.send(FRAME.RESET, id)
      return
    }
    const head = parseJson(decoder.decode(payload), 'request head')
    const stream = { kind: 'exchange', abort: new AbortController(), bodyController: undefined }
    const body = new ReadableStream({
      start: (controller) => { stream.bodyController = controller },
    })
    this.streams.set(id, stream)
    let responded = false
    const exchange = {
      method: String(head.m ?? 'GET').toUpperCase(),
      path: String(head.p ?? '/'),
      headers: Array.isArray(head.h) ? head.h.filter((pair) => Array.isArray(pair) && pair.length === 2).map(([name, value]) => [String(name).toLowerCase(), String(value)]) : [],
      body,
      signal: stream.abort.signal,
      respond: (status, statusText, headers) => {
        if (responded || this.streams.get(id) !== stream) return
        responded = true
        this.sendJson(FRAME.RESPONSE, id, { s: status, st: statusText ?? '', h: headerPairs(headers) })
      },
      write: (bytes) => this.writeData(id, stream, asBytes(bytes)),
      end: () => {
        if (this.streams.get(id) !== stream) return
        this.streams.delete(id)
        this.send(FRAME.END, id)
      },
      fail: (message) => {
        if (this.streams.get(id) !== stream) return
        this.streams.delete(id)
        stream.abort.abort(new Error(message))
        this.sendJson(FRAME.RESET, id, { e: message })
      },
    }
    Promise.resolve().then(() => this.handlers.request(exchange)).catch((error) => { exchange.fail(String(error?.message ?? error)) })
  }

  receiveExchange(id, stream, type, payload) {
    if (type === FRAME.DATA) {
      try { stream.bodyController?.enqueue(payload) } catch (_closed) { /* the handler cancelled the request body */ }
    } else if (type === FRAME.END) {
      try { stream.bodyController?.close() } catch (_closed) { /* the handler cancelled the request body */ }
    } else if (type === FRAME.RESET) {
      this.failStream(id, stream, new TunnelError('reset', 'The client cancelled the request'))
    }
  }

  acceptSession(id, payload) {
    if (this.handlers.websocket === undefined || this.streams.has(id)) {
      this.send(FRAME.RESET, id)
      return
    }
    const head = parseJson(decoder.decode(payload), 'socket head')
    let closedNotified = false
    const stream = {
      kind: 'session',
      fragments: [],
      session: undefined,
      notifyClose: (code, reason) => {
        if (closedNotified) return
        closedNotified = true
        stream.session.onclose?.(code, reason)
      },
    }
    this.streams.set(id, stream)
    const session = {
      path: String(head.p ?? '/'),
      protocols: Array.isArray(head.s) ? head.s.map(String) : [],
      headers: Array.isArray(head.h) ? head.h : [],
      /** @type {((data: string | Uint8Array, isText: boolean) => void) | undefined} */
      onmessage: undefined,
      /** @type {((code: number, reason: string) => void) | undefined} */
      onclose: undefined,
      accept: (protocol) => { if (this.streams.get(id) === stream) this.sendJson(FRAME.WS_ACCEPT, id, { s: protocol ?? '' }) },
      sendText: (text) => { if (this.streams.get(id) === stream) this.sendMessage(id, encoder.encode(text), true) },
      sendBinary: (bytes) => { if (this.streams.get(id) === stream) this.sendMessage(id, asBytes(bytes), false) },
      close: (code, reason) => {
        if (this.streams.get(id) !== stream) return
        this.streams.delete(id)
        closedNotified = true
        this.sendJson(FRAME.WS_CLOSE, id, { c: code, r: reason ?? '' })
      },
      fail: (message) => {
        if (this.streams.get(id) !== stream) return
        this.streams.delete(id)
        closedNotified = true
        this.sendJson(FRAME.WS_CLOSE, id, { c: 1011, r: String(message).slice(0, 120) })
      },
    }
    stream.session = session
    Promise.resolve().then(() => this.handlers.websocket(session)).catch((error) => { session.fail(String(error?.message ?? error)) })
  }

  receiveSession(id, stream, type, payload) {
    const { session } = stream
    if (type === FRAME.WS_FRAGMENT) {
      stream.fragments.push(payload.slice())
    } else if (type === FRAME.WS_TEXT || type === FRAME.WS_BINARY) {
      const whole = stream.fragments.length === 0 ? payload : concatBytes(...stream.fragments.splice(0), payload)
      session.onmessage?.(type === FRAME.WS_TEXT ? decoder.decode(whole) : whole.slice(), type === FRAME.WS_TEXT)
    } else if (type === FRAME.WS_CLOSE) {
      const info = parseJson(decoder.decode(payload), 'close')
      this.streams.delete(id)
      this.sendJson(FRAME.WS_CLOSE, id, { c: Number(info.c) || 1000, r: String(info.r ?? '') })
      stream.notifyClose(Number(info.c) || 1000, String(info.r ?? ''))
    } else if (type === FRAME.RESET) {
      this.failStream(id, stream, new TunnelError('reset', 'The client reset the socket'))
    }
  }

  shutdown(code, reason) {
    if (this.closed) return
    this.closed = true
    clearInterval(this.keepAlive)
    const error = new TunnelError('closed', `The tunnel closed (${code}${reason ? `: ${reason}` : ''})`)
    for (const waiter of [...this.pings]) waiter.done(error)
    for (const [id, stream] of [...this.streams]) this.failStream(id, stream, error)
    this.streams.clear()
    this.onclose?.(code, reason)
  }
}

// ---------------------------------------------------------------------------
// Client session manager
// ---------------------------------------------------------------------------

/** How long one relay keeps the race to itself before the next relay is tried as well. */
export const RELAY_HEADSTART_MS = 1500
const PROBE_TIMEOUT_MS = 10_000

/**
 * Connect through the first relay that completes the handshake. Relays start in priority order:
 * each one gets {@link RELAY_HEADSTART_MS} before the next starts too, and a failure starts the
 * next at once. The first success wins and the attempts still running are abandoned. A failure
 * that retrying cannot fix starts no further relays; when nothing succeeds, that failure is
 * reported, otherwise the failure of the highest-priority relay.
 * @param {Omit<Parameters<typeof connectClient>[0], 'relayUrl'> & { relayUrls: string[], headstartMs?: number }} options - {@link connectClient} options with a relay list.
 * @returns {Promise<Awaited<ReturnType<typeof connectClient>> & { relayUrl: string }>} the ready channel and the relay that carried it.
 */
export function connectAny({ relayUrls, headstartMs = RELAY_HEADSTART_MS, signal, ...options }) {
  return new Promise((resolve, reject) => {
    const attempts = []
    const errors = []
    let started = 0
    let running = 0
    let done = false
    let blocked = false
    let timer
    const settle = () => {
      done = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', cancel)
    }
    const cancel = () => {
      if (done) return
      settle()
      for (const attempt of attempts) attempt.abort()
      reject(new TunnelError('stopped', 'Cancelled'))
    }
    const fail = () => {
      settle()
      const failures = errors.filter(Boolean)
      reject(failures.find((error) => error instanceof TunnelError && FATAL_CODES.has(error.code))
        ?? failures[0] ?? new TunnelError('unconfigured', 'No relay address is known for this DSH'))
    }
    const launch = () => {
      clearTimeout(timer)
      if (done) return
      if (blocked || started >= relayUrls.length) {
        if (running === 0) fail()
        return
      }
      const index = started
      started += 1
      running += 1
      const attempt = new AbortController()
      attempts[index] = attempt
      timer = setTimeout(launch, headstartMs)
      connectClient({ ...options, relayUrl: relayUrls[index], signal: attempt.signal }).then((result) => {
        running -= 1
        if (done) {
          result.channel.close(1000, 'superseded')
          return
        }
        settle()
        attempts.forEach((other, position) => { if (position !== index) other.abort() })
        resolve({ ...result, relayUrl: relayUrls[index] })
      }, (error) => {
        running -= 1
        errors[index] = error
        if (done) return
        if (error instanceof TunnelError && FATAL_CODES.has(error.code)) blocked = true
        launch()
      })
    }
    if (signal?.aborted) {
      reject(new TunnelError('stopped', 'Cancelled'))
      return
    }
    signal?.addEventListener('abort', cancel, { once: true })
    launch()
  })
}

/**
 * Pair a device with a host using a one-time code.
 * @param {{ pairing: ReturnType<typeof decodePairing>, device: { privateKey: CryptoKey, publicJwk: object }, deviceName: string }} options - offer and device.
 * @returns {Promise<{ hostName: string, device: { id: string, name: string }, relayUrls: string[] }>} the host's acknowledgement and the relays to keep.
 */
export async function pairDevice({ pairing, device, deviceName }) {
  if (pairing.expiresAt !== 0 && pairing.expiresAt < Date.now()) {
    throw new TunnelError('pairing-invalid', 'This pairing code has expired; create a new one in DSH settings')
  }
  const result = await connectAny({
    relayUrls: normalizeRelayList(pairing.relayUrls ?? pairing.relayUrl),
    serverId: pairing.serverId,
    device,
    deviceName,
    mode: 'pair',
    pairing,
  })
  result.channel.close(1000, 'paired')
  return { hostName: result.hostName, device: result.device, relayUrls: result.relays ?? normalizeRelayList(pairing.relayUrls ?? pairing.relayUrl) }
}

/**
 * Keeps one authenticated tunnel to a paired host, reconnecting with backoff, and exposes request
 * and WebSocket operations that wait for the tunnel. Each connection picks a relay with
 * {@link connectAny}; an open tunnel stays on its relay until it drops, even when a relay with a
 * higher priority recovers. A preferred relay, chosen by the user, is tried first; the other relays
 * still follow it in priority order, so a preferred relay that is down does not cut the device off.
 */
export class RemoteHost {
  /**
   * @param {object} options - host record and observers.
   * @param {string[]} options.relayUrls - relay socket URLs in priority order (`relayUrl` is read for older records).
   * @param {string} options.serverId - host key id.
   * @param {{ privateKey: CryptoKey, publicJwk: object }} options.device - device identity.
   * @param {string} options.deviceName - name reported to the host.
   * @param {(status: { state: string, error?: string, code?: string, hostName?: string, relayUrl?: string, generation?: number }) => void} [options.onstatus] - status observer; `generation` numbers each opened tunnel.
   * @param {(relayUrls: string[]) => void} [options.onrelays] - the host offers a different relay list; store it.
   * @param {string} [options.preferredRelay] - relay to try first while the host still offers it.
   */
  constructor(options) {
    this.options = options
    this.relayUrls = normalizeRelayList(options.relayUrls ?? options.relayUrl)
    this.preferred = normalizeRelayList(options.preferredRelay ?? [])[0]
    this.switching = false
    /** Counts opened tunnels, so an observer can tell a new connection from the one it saw before. */
    this.generation = 0
    /** Relay carrying the open tunnel. */
    this.relayUrl = undefined
    this.running = false
    this.mux = undefined
    this.waiters = []
    this.wake = undefined
    this.status = { state: 'idle' }
  }

  setStatus(status) {
    this.status = status
    this.options.onstatus?.(status)
  }

  /** Start connecting; repeated calls are ignored while running. */
  start() {
    if (this.running) return
    this.running = true
    void this.loop()
  }

  /** Close the tunnel and stop reconnecting. */
  stop() {
    this.running = false
    this.attempt?.abort()
    this.wake?.abort()
    this.mux?.close()
    const error = new TunnelError('stopped', 'Disconnected')
    for (const waiter of this.waiters.splice(0)) waiter.reject(error)
  }

  /**
   * Keep the relay list a handshake reported; hosts before 0.4.0 report none.
   * @param {string[] | undefined} relays - relays the host offers now, in priority order.
   */
  learn(relays) {
    if (relays === undefined || relays.length === 0 || sameList(relays, this.relayUrls)) return
    this.relayUrls = relays
    this.options.onrelays?.(relays)
  }

  /** Relays in the order the next connection tries them. */
  order() {
    const preferred = this.preferred
    return preferred !== undefined && this.relayUrls.includes(preferred)
      ? [preferred, ...this.relayUrls.filter((relayUrl) => relayUrl !== preferred)]
      : this.relayUrls
  }

  /**
   * Prefer one relay, or none, from now on. When the open tunnel uses another relay, it is closed
   * and the next connection tries the preferred relay first; requests and sockets in flight fail
   * and their pages reconnect.
   * @param {string | null} relayUrl - relay to prefer, or null to follow the host's priority again.
   * @param {number} [timeoutMs] - how long to wait for the tunnel to come back.
   * @returns {Promise<void>} settles once a tunnel is open again.
   */
  async prefer(relayUrl, timeoutMs = 30_000) {
    this.preferred = relayUrl === null ? undefined : normalizeRelayList(relayUrl)[0]
    if (!this.running) return
    const mux = this.mux
    if (this.preferred !== undefined && mux !== undefined && !mux.closed && this.relayUrl !== this.preferred) {
      this.switching = true
      this.mux = undefined
      mux.close()
    }
    await this.ready(timeoutMs)
  }

  /** Skip the current backoff delay, for example when the network returns. */
  retryNow() {
    this.wake?.abort()
  }

  async loop() {
    let failures = 0
    while (this.running) {
      this.setStatus({ state: 'connecting', ...failures > 0 ? { error: this.status.error } : {} })
      try {
        this.attempt = new AbortController()
        const { channel, hostName, relays, relayUrl } = await connectAny({ ...this.options, relayUrls: this.order(), mode: 'auth', signal: this.attempt.signal })
        this.attempt = undefined
        if (!this.running) {
          channel.close(1000, 'stopped')
          return
        }
        this.learn(relays)
        const mux = new Mux(channel, { keepAliveMs: 20_000 })
        const closed = new Promise((resolve) => { mux.onclose = (code, reason) => { resolve({ code, reason }) } })
        this.mux = mux
        this.relayUrl = relayUrl
        failures = 0
        this.generation += 1
        this.setStatus({ state: 'connected', hostName, relayUrl, generation: this.generation })
        for (const waiter of this.waiters.splice(0)) waiter.resolve(mux)
        const { code, reason } = await closed
        if (this.mux === mux) this.mux = undefined
        this.relayUrl = undefined
        if (!this.running) return
        // A switch the user asked for is not a lost connection.
        if (this.switching) this.setStatus({ state: 'connecting' })
        else this.setStatus({ state: 'connecting', error: `Connection lost (${code}${reason ? `: ${reason}` : ''})` })
        this.switching = false
      } catch (error) {
        if (!this.running) return
        const code = error instanceof TunnelError ? error.code : 'error'
        if (FATAL_CODES.has(code)) {
          this.running = false
          this.setStatus({ state: 'rejected', code, error: error.message })
          for (const waiter of this.waiters.splice(0)) waiter.reject(error)
          return
        }
        failures += 1
        this.setStatus({ state: 'retrying', code, error: String(error?.message ?? error) })
      }
      this.wake = new AbortController()
      const delay = failures === 0 ? 250 : Math.min(15_000, 500 * 2 ** Math.min(failures - 1, 5)) * (0.75 + Math.random() * 0.5)
      await sleep(delay, this.wake.signal)
      this.wake = undefined
    }
  }

  /**
   * Measure the round trip to the host through every known relay; see {@link RemoteHost#probeOne}.
   * @param {number} [timeoutMs] - deadline per relay.
   * @returns {Promise<Array<Awaited<ReturnType<RemoteHost['probeOne']>>>>} one entry per relay, in the host's priority order.
   */
  async probe(timeoutMs = PROBE_TIMEOUT_MS) {
    return await Promise.all(this.relayUrls.map((relayUrl) => this.probeOne(relayUrl, timeoutMs)))
  }

  /**
   * Measure the end-to-end round trip to the host through one relay. The relay carrying the open
   * tunnel is measured in place; any other relay gets a short-lived probe connection, whose
   * handshake is not counted. Nothing switches relays.
   * @param {string} relayUrl - one of the host's relays.
   * @param {number} [timeoutMs] - deadline for this relay.
   * @returns {Promise<{ relayUrl: string, current: boolean, preferred: boolean, ms: number | null, code?: string, error?: string }>} the measurement.
   */
  async probeOne(relayUrl, timeoutMs = PROBE_TIMEOUT_MS) {
    const mux = this.mux !== undefined && !this.mux.closed ? this.mux : undefined
    const entry = { relayUrl, current: mux !== undefined && relayUrl === this.relayUrl, preferred: relayUrl === this.preferred }
    const attempt = new AbortController()
    let timer
    try {
      const deadline = new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
          attempt.abort()
          reject(new TunnelError('timeout', 'No answer in time'))
        }, timeoutMs)
      })
      if (entry.current) {
        // The open tunnel learned the host's relays when it connected; ask again alongside.
        void this.lookup(relayUrl, timeoutMs)
        return { ...entry, ms: await Promise.race([mux.ping(timeoutMs), deadline]) }
      }
      const connecting = connectClient({ ...this.options, relayUrl, mode: 'auth', probe: true, signal: attempt.signal })
      // A handshake that completes after the deadline is closed rather than left open.
      connecting.then(({ channel }) => { if (attempt.signal.aborted) channel.close(1000, 'probe') }, () => {})
      const { channel, relays } = await Promise.race([connecting, deadline])
      this.learn(relays)
      const probe = new Mux(channel, { keepAliveMs: timeoutMs })
      try {
        return { ...entry, ms: await Promise.race([probe.ping(timeoutMs), deadline]) }
      } finally {
        probe.close()
      }
    } catch (error) {
      return { ...entry, ms: null, code: error instanceof TunnelError ? error.code : 'error', error: String(error?.message ?? error) }
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Ask the host which relays it offers now, through a short-lived probe connection. An open
   * tunnel hears the list only when it connects, so a relay the host added later would otherwise
   * stay unknown until the tunnel reconnects. A failure changes nothing.
   * @param {string} relayUrl - relay to ask through.
   * @param {number} [timeoutMs] - deadline.
   * @returns {Promise<void>} settles once the list is known or the attempt is abandoned.
   */
  async lookup(relayUrl, timeoutMs = PROBE_TIMEOUT_MS) {
    const attempt = new AbortController()
    const timer = setTimeout(() => { attempt.abort() }, timeoutMs)
    try {
      const { channel, relays } = await connectClient({ ...this.options, relayUrl, mode: 'auth', probe: true, signal: attempt.signal })
      channel.close(1000, 'probe')
      this.learn(relays)
    } catch {
      // The measurement over the open tunnel reports how this relay is doing.
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Wait for a connected tunnel.
   * @param {number} [timeoutMs] - deadline.
   * @returns {Promise<Mux>} the live multiplexer.
   */
  ready(timeoutMs = 30_000) {
    if (this.mux !== undefined && !this.mux.closed) return Promise.resolve(this.mux)
    if (!this.running) return Promise.reject(new TunnelError('stopped', 'Not connected'))
    return new Promise((resolve, reject) => {
      const waiter = {
        resolve: (mux) => { clearTimeout(timer); resolve(mux) },
        reject: (error) => { clearTimeout(timer); reject(error) },
      }
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter)
        if (index >= 0) this.waiters.splice(index, 1)
        reject(new TunnelError('timeout', 'The DSH host is not reachable right now'))
      }, timeoutMs)
      this.waiters.push(waiter)
    })
  }

  /**
   * @param {Parameters<Mux['request']>[0]} init - request.
   * @param {AbortSignal} [signal] - cancellation.
   * @returns {ReturnType<Mux['request']>} response.
   */
  async request(init, signal) {
    const mux = await this.ready()
    return await mux.request(init, signal)
  }

  /**
   * @param {string} url - URL reported by the returned socket.
   * @param {string} path - host path and query.
   * @param {{ protocols?: string[], headers?: Array<[string, string]> }} [options] - socket options.
   * @returns {TunnelSocket} socket that opens once the tunnel is ready.
   */
  openWebSocket(url, path, options) {
    const socket = new TunnelSocket(url)
    this.ready().then(
      (mux) => { mux.attachWebSocket(socket, path, options) },
      () => { socket.fail() },
    )
    return socket
  }
}
