/**
 * DSH remote launcher: pairs this browser with a DSH host, keeps the encrypted tunnel, and shows the
 * host's Web GUI in an iframe whose requests the service worker hands back to this window.
 *
 * The device key is a non-extractable WebCrypto key stored in IndexedDB, so script on this origin
 * can use it but cannot copy it. Serve the launcher from an origin that hosts nothing else.
 */
import { RemoteHost, TunnelError, createIdentity, decodePairing, pairDevice } from './tunnel.js'

const TEXT = {
  en: {
    pairTitle: 'Pair this device',
    pairIntro: 'Pair with “{host}”. The code is valid until {time}.',
    deviceName: 'Device name shown in DSH',
    pairRisk: 'A paired device gets full control of that DSH, including running commands. Only pair devices you own.',
    pairAction: 'Pair',
    pairing: 'Pairing…',
    cancel: 'Cancel',
    hostsTitle: 'Paired DSH',
    emptyIntro: 'No DSH is paired with this browser yet.',
    step1: 'In DSH, open Settings → Remote access.',
    step2: 'Turn on remote access and choose “Pair a device”.',
    step3: 'Scan the QR code with this device, or open the pairing link here.',
    open: 'Open',
    forget: 'Remove',
    forgetConfirm: 'Remove “{host}” from this browser? Remove the device in DSH Settings as well.',
    pairedAt: 'Paired {date}',
    footer: 'Traffic is end-to-end encrypted between this browser and your DSH; the relay only forwards ciphertext.',
    connecting: 'Connecting to {host}…',
    retrying: 'Cannot reach {host}: {error}',
    connected: 'Connected to {host}',
    rejected: 'This device is no longer paired with {host}.',
    failed: '{error}',
    loading: 'Loading…',
    retry: 'Retry',
    leave: 'Leave',
    noWorker: 'This browser cannot run the launcher: service workers are unavailable. Use HTTPS and a current browser; private browsing modes may block them.',
    noCrypto: 'This page must be served over HTTPS.',
    expired: 'This pairing code has expired. Create a new one in DSH settings.',
  },
  zh: {
    pairTitle: '配对此设备',
    pairIntro: '与“{host}”配对。配对码在 {time} 前有效。',
    deviceName: '在 DSH 中显示的设备名称',
    pairRisk: '配对后，此设备可以完全控制该 DSH，包括执行命令。只配对你自己的设备。',
    pairAction: '配对',
    pairing: '正在配对…',
    cancel: '取消',
    hostsTitle: '已配对的 DSH',
    emptyIntro: '这个浏览器还没有配对任何 DSH。',
    step1: '在 DSH 中打开“设置 → 远程访问”。',
    step2: '开启远程访问，然后选择“配对新设备”。',
    step3: '用这台设备扫描二维码，或在这里打开配对链接。',
    open: '打开',
    forget: '移除',
    forgetConfirm: '要从此浏览器移除“{host}”吗？也请在 DSH 设置中移除这台设备。',
    pairedAt: '配对于 {date}',
    footer: '浏览器与 DSH 之间端到端加密，中转服务器只转发密文。',
    connecting: '正在连接 {host}…',
    retrying: '无法连接 {host}：{error}',
    connected: '已连接 {host}',
    rejected: '此设备已不再与 {host} 配对。',
    failed: '{error}',
    loading: '正在加载…',
    retry: '重试',
    leave: '离开',
    noWorker: '此浏览器无法运行启动页：Service Worker 不可用。请使用 HTTPS 和较新的浏览器；无痕模式可能会禁用它。',
    noCrypto: '此页面必须通过 HTTPS 打开。',
    expired: '配对码已过期，请在 DSH 设置中重新生成。',
  },
}
const LANG = /^zh\b/i.test(navigator.language ?? '') ? 'zh' : 'en'
const encoder = new TextEncoder()
const APP_SCOPE = new URL('./app/', location.href)
const CARRIER = '<script>(function(){try{var b=window.parent!==window&&window.parent.__DSH_REMOTE__;if(b){window.__DSH_TRANSPORT__={createWebSocket:function(u){return b.openWebSocket(u)}}}}catch(e){}})();</script>'
const DROPPED_REQUEST_HEADERS = new Set(['cookie', 'origin', 'referer', 'accept-encoding', 'service-worker', 'service-worker-navigation-preload'])
const DROPPED_RESPONSE_HEADERS = new Set(['x-frame-options', 'set-cookie', 'clear-site-data'])

function t(key, vars = {}) {
  const template = TEXT[LANG][key] ?? TEXT.en[key] ?? key
  return template.replace(/\{(\w+)\}/g, (_, name) => String(vars[name] ?? ''))
}

const $ = (id) => document.getElementById(id)

function applyStaticText() {
  document.documentElement.lang = LANG === 'zh' ? 'zh-CN' : 'en'
  for (const element of document.querySelectorAll('[data-text]')) element.textContent = t(element.dataset.text)
}

function showError(element, message) {
  element.hidden = message === undefined || message === ''
  element.textContent = message ?? ''
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

let database
function openDatabase() {
  database ??= new Promise((resolve, reject) => {
    const request = indexedDB.open('dsh-remote', 1)
    request.onupgradeneeded = () => { request.result.createObjectStore('hosts', { keyPath: 'serverId' }) }
    request.onsuccess = () => { resolve(request.result) }
    request.onerror = () => { reject(request.error) }
  })
  return database
}

async function store(mode, operate) {
  const db = await openDatabase()
  return await new Promise((resolve, reject) => {
    const transaction = db.transaction('hosts', mode)
    const request = operate(transaction.objectStore('hosts'))
    transaction.oncomplete = () => { resolve(request?.result) }
    transaction.onerror = () => { reject(transaction.error) }
    transaction.onabort = () => { reject(transaction.error) }
  })
}

const listHosts = () => store('readonly', (hosts) => hosts.getAll())
const saveHost = (host) => store('readwrite', (hosts) => hosts.put(host))
const deleteHost = (serverId) => store('readwrite', (hosts) => hosts.delete(serverId))

// ---------------------------------------------------------------------------
// Service worker bridge
// ---------------------------------------------------------------------------

let workerClientId

async function ensureWorker() {
  if (!('serviceWorker' in navigator)) throw new Error(t('noWorker'))
  const registration = await navigator.serviceWorker.register('./sw.js', { scope: APP_SCOPE.pathname })
  const worker = registration.active ?? await new Promise((resolve) => {
    const candidate = registration.installing ?? registration.waiting
    candidate.addEventListener('statechange', () => { if (candidate.state === 'activated') resolve(candidate) })
  })
  if (workerClientId === undefined) {
    const nonce = crypto.randomUUID()
    workerClientId = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { reject(new Error(t('noWorker'))) }, 5000)
      const onMessage = (event) => {
        if (event.data?.type !== 'dsh-remote:whoami' || event.data.nonce !== nonce) return
        clearTimeout(timer)
        navigator.serviceWorker.removeEventListener('message', onMessage)
        resolve(event.data.id)
      }
      navigator.serviceWorker.addEventListener('message', onMessage)
      worker.postMessage({ type: 'dsh-remote:whoami', nonce })
    })
  }
  return workerClientId
}

function headerValue(headers, name) {
  return headers.find(([key]) => key === name)?.[1]
}

function streamOf(bytes) {
  return new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close() } })
}

function injectCarrier(html) {
  const head = /<head(\s[^>]*)?>/i.exec(html)
  if (head === null) return CARRIER + html
  return html.slice(0, head.index + head[0].length) + CARRIER + html.slice(head.index + head[0].length)
}

function withoutFrameAncestors(value) {
  return value.split(';').filter((directive) => !/^\s*frame-ancestors\b/i.test(directive)).join(';')
}

async function serveFetch(request, port) {
  const session = current
  if (session === undefined || request.token !== workerClientId) {
    port.postMessage({ type: 'error', status: 503, message: 'not connected' })
    return
  }
  const abort = new AbortController()
  port.onmessage = (event) => { if (event.data?.type === 'cancel') abort.abort() }
  const decompress = typeof DecompressionStream === 'function'
  const headers = request.headers.filter(([name]) => !DROPPED_REQUEST_HEADERS.has(name))
  headers.push(['accept-encoding', decompress ? 'gzip' : 'identity'])
  try {
    const response = await session.remote.request({
      method: request.method,
      path: request.path,
      headers,
      body: request.body ? new Uint8Array(request.body) : null,
    }, abort.signal)
    let body = response.body
    let responseHeaders = response.headers
      .filter(([name]) => !DROPPED_RESPONSE_HEADERS.has(name))
      .map(([name, value]) => [name, name === 'content-security-policy' ? withoutFrameAncestors(value) : value])
    if (body !== null && decompress && headerValue(responseHeaders, 'content-encoding') === 'gzip') {
      body = body.pipeThrough(new DecompressionStream('gzip'))
      responseHeaders = responseHeaders.filter(([name]) => name !== 'content-encoding' && name !== 'content-length')
    }
    if (body !== null && request.mode === 'navigate' && /text\/html/i.test(headerValue(responseHeaders, 'content-type') ?? '')) {
      body = streamOf(encoder.encode(injectCarrier(await new Response(body).text())))
      responseHeaders = responseHeaders.filter(([name]) => name !== 'content-length')
    }
    port.postMessage({ type: 'head', status: response.status, statusText: response.statusText, headers: responseHeaders })
    if (body !== null) {
      const reader = body.getReader()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        const copy = value.slice()
        port.postMessage({ type: 'chunk', data: copy.buffer }, [copy.buffer])
      }
    }
    port.postMessage({ type: 'end' })
  } catch (error) {
    port.postMessage({ type: 'error', message: error?.message ?? String(error) })
  }
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', (event) => {
    if (event.data?.type === 'dsh-remote:fetch' && event.ports[0] !== undefined) void serveFetch(event.data, event.ports[0])
  })
  navigator.serviceWorker.startMessages()
}

/** WebSocket transport the carrier script in the embedded page calls. */
window.__DSH_REMOTE__ = {
  openWebSocket(url) {
    const session = current
    const target = new URL(url)
    const prefix = `${APP_SCOPE.pathname}${workerClientId}`
    const pathname = target.pathname.startsWith(`${prefix}/`) ? target.pathname.slice(prefix.length) : target.pathname
    if (session === undefined) throw new Error('not connected')
    return session.remote.openWebSocket(url, `${pathname}${target.search}`)
  },
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/** @type {{ host: object, remote: RemoteHost } | undefined} */
let current
let chipTimer

function guessDeviceName() {
  const agent = navigator.userAgent
  const device = /iPhone/.test(agent) ? 'iPhone' : /iPad/.test(agent) ? 'iPad' : /Android/.test(agent) ? 'Android'
    : /Macintosh/.test(agent) ? 'Mac' : /Windows/.test(agent) ? 'Windows' : /Linux/.test(agent) ? 'Linux' : 'Browser'
  const browser = /Edg\//.test(agent) ? 'Edge' : /Firefox\//.test(agent) ? 'Firefox' : /Chrome\//.test(agent) ? 'Chrome' : /Safari\//.test(agent) ? 'Safari' : ''
  return browser ? `${device} ${browser}` : device
}

async function renderHosts() {
  const hosts = (await listHosts()).sort((a, b) => b.pairedAt - a.pairedAt)
  const list = $('hosts')
  list.replaceChildren()
  $('empty').hidden = hosts.length > 0
  for (const host of hosts) {
    const row = document.createElement('div')
    row.className = 'row'
    row.style.padding = '6px 0'
    const info = document.createElement('div')
    info.className = 'grow'
    const name = document.createElement('div')
    name.className = 'name'
    name.textContent = host.hostName || host.serverId.slice(0, 8)
    const sub = document.createElement('div')
    sub.className = 'sub'
    sub.textContent = `${new URL(host.relayUrl).host} · ${t('pairedAt', { date: new Date(host.pairedAt).toLocaleDateString() })}`
    info.append(name, sub)
    const forget = document.createElement('button')
    forget.type = 'button'
    forget.className = 'danger'
    forget.textContent = t('forget')
    forget.addEventListener('click', async () => {
      if (!confirm(t('forgetConfirm', { host: host.hostName }))) return
      await deleteHost(host.serverId)
      await renderHosts()
    })
    const open = document.createElement('button')
    open.type = 'button'
    open.className = 'primary'
    open.textContent = t('open')
    open.addEventListener('click', () => { void openSession(host) })
    row.append(info, forget, open)
    list.append(row)
  }
}

function showHome() {
  $('session').hidden = true
  $('home').hidden = false
  void renderHosts()
}

function setChip(state, text, collapsible) {
  const chip = $('chip')
  chip.dataset.state = state
  delete chip.dataset.collapsed
  chip.querySelector('.text').textContent = text
  chip.querySelector('.text').hidden = false
  $('chip-leave').hidden = false
  $('chip-retry').hidden = state !== 'retrying' && state !== 'connecting'
  clearTimeout(chipTimer)
  if (collapsible) {
    chipTimer = setTimeout(() => {
      chip.dataset.collapsed = ''
      chip.querySelector('.text').hidden = true
      $('chip-leave').hidden = true
      $('chip-retry').hidden = true
    }, 3000)
  }
}

async function openSession(host) {
  showError($('home-error'), '')
  let token
  try {
    token = await ensureWorker()
  } catch (error) {
    showError($('home-error'), error.message)
    return
  }
  closeSession()
  const label = host.hostName || host.serverId.slice(0, 8)
  const remote = new RemoteHost({
    relayUrl: host.relayUrl,
    serverId: host.serverId,
    device: { privateKey: host.privateKey, publicJwk: host.publicJwk },
    deviceName: host.deviceName,
    onstatus: (status) => {
      if (current?.remote !== remote) return
      if (status.state === 'connected') {
        setChip('connected', t('connected', { host: label }), true)
        if (!session.loaded) {
          session.loaded = true
          $('veil').textContent = ''
          frame.src = `${APP_SCOPE.href}${token}/`
        }
      } else if (status.state === 'rejected') {
        setChip('rejected', status.code === 'unknown-device' ? t('rejected', { host: label }) : t('failed', { error: status.error }), false)
      } else if (status.state === 'retrying') {
        setChip('retrying', t('retrying', { host: label, error: status.error }), false)
      } else {
        setChip('connecting', t('connecting', { host: label }), false)
      }
    },
  })
  const frame = document.createElement('iframe')
  frame.title = label
  frame.allow = 'clipboard-read; clipboard-write; microphone; fullscreen'
  frame.style.visibility = 'hidden'
  frame.addEventListener('load', () => { frame.style.visibility = 'visible' })
  const session = { host, remote, frame, loaded: false }
  current = session
  $('veil').textContent = t('loading')
  $('session').append(frame)
  $('home').hidden = true
  $('session').hidden = false
  localStorage.setItem('dsh-remote:last', host.serverId)
  remote.start()
}

function closeSession() {
  const session = current
  current = undefined
  if (session === undefined) return
  session.remote.stop()
  session.frame.remove()
}

async function startPairing(code) {
  let pairing
  try {
    pairing = decodePairing(code)
  } catch (error) {
    showError($('home-error'), error.message)
    return
  }
  const card = $('pair-card')
  card.hidden = false
  const hostsCard = $('hosts-card')
  hostsCard.hidden = (await listHosts()).length === 0
  $('pair-intro').textContent = t('pairIntro', { host: pairing.hostName || pairing.serverId.slice(0, 8), time: new Date(pairing.expiresAt).toLocaleTimeString() })
  const nameInput = $('device-name')
  nameInput.value = guessDeviceName()
  const confirmButton = $('pair-confirm')
  if (pairing.expiresAt !== 0 && pairing.expiresAt < Date.now()) showError($('pair-error'), t('expired'))
  $('pair-cancel').onclick = () => {
    card.hidden = true
    hostsCard.hidden = false
    history.replaceState(null, '', location.pathname + location.search)
  }
  confirmButton.onclick = async () => {
    showError($('pair-error'), '')
    confirmButton.disabled = true
    confirmButton.textContent = t('pairing')
    try {
      const device = await createIdentity({ extractable: false })
      const deviceName = nameInput.value.trim() || guessDeviceName()
      const result = await pairDevice({ pairing, device, deviceName })
      const host = {
        serverId: pairing.serverId,
        relayUrl: pairing.relayUrl,
        hostName: result.hostName || pairing.hostName,
        deviceId: device.id,
        deviceName: result.device.name || deviceName,
        privateKey: device.privateKey,
        publicJwk: device.publicJwk,
        pairedAt: Date.now(),
      }
      await saveHost(host)
      history.replaceState(null, '', location.pathname + location.search)
      card.hidden = true
      hostsCard.hidden = false
      await renderHosts()
      void openSession(host)
    } catch (error) {
      showError($('pair-error'), error instanceof TunnelError && error.code === 'pairing-invalid' ? `${error.message}` : error?.message ?? String(error))
    } finally {
      confirmButton.disabled = false
      confirmButton.textContent = t('pairAction')
    }
  }
}

async function main() {
  applyStaticText()
  $('chip-leave').addEventListener('click', () => {
    closeSession()
    localStorage.removeItem('dsh-remote:last')
    showHome()
  })
  $('chip-retry').addEventListener('click', () => { current?.remote.retryNow() })
  $('chip').addEventListener('click', (event) => {
    if (event.target.closest('button')) return
    const text = $('chip').querySelector('.text')
    if (text.hidden) setChip($('chip').dataset.state, text.textContent, true)
  })
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') current?.remote.retryNow() })
  window.addEventListener('online', () => { current?.remote.retryNow() })
  if (globalThis.crypto?.subtle === undefined) {
    $('home').hidden = false
    showError($('home-error'), t('noCrypto'))
    return
  }
  showHome()
  const code = location.hash.slice(1)
  if (code.includes('k=') && code.includes('s=')) {
    await startPairing(code)
    return
  }
  const last = localStorage.getItem('dsh-remote:last')
  if (last !== null) {
    const host = (await listHosts()).find((candidate) => candidate.serverId === last)
    if (host !== undefined) void openSession(host)
  }
}

void main()
