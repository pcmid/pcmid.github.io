/**
 * DSH remote launcher: pairs this browser with a DSH host, keeps the encrypted tunnel, and shows the
 * host's Web GUI in an iframe whose requests the service worker hands back to this window.
 *
 * The device key is a non-extractable WebCrypto key stored in IndexedDB, so script on this origin
 * can use it but cannot copy it. Serve the launcher from an origin that hosts nothing else.
 */
// index.html loads this file as `app.js?v=<version>`; the same query reaches the other scripts, so a
// CDN that caches script files for hours cannot pair a new app.js with an old tunnel.js.
const RELEASE = new URL(import.meta.url).search
const { RemoteHost, TunnelError, createIdentity, decodePairing, pairDevice } = await import(`./tunnel.js${RELEASE}`)

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
    step3: 'Scan the QR code with this device, or paste the pairing link below.',
    addTitle: 'Add a DSH',
    addIntro: 'Paste the pairing link from DSH Settings → Remote access, or scan its QR code.',
    pastePlaceholder: 'Pairing link',
    next: 'Next',
    scan: 'Scan QR code',
    invalidCode: 'This is not a DSH pairing link. Copy the whole link from DSH settings.',
    notPairingQr: 'This QR code is not a DSH pairing link.',
    noCamera: 'This browser cannot open the camera. Paste the pairing link instead.',
    cameraDenied: 'Camera access was denied. Allow it in the browser settings, or paste the pairing link.',
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
    state_connected: 'Connected',
    state_connecting: 'Connecting…',
    state_retrying: 'Cannot connect',
    state_rejected: 'No longer paired',
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
    step3: '用这台设备扫描二维码，或在下方粘贴配对链接。',
    addTitle: '添加 DSH',
    addIntro: '粘贴 DSH“设置 → 远程访问”中生成的配对链接，或扫描它的二维码。',
    pastePlaceholder: '配对链接',
    next: '下一步',
    scan: '扫描二维码',
    invalidCode: '这不是 DSH 配对链接，请从 DSH 设置中复制完整的链接。',
    notPairingQr: '这个二维码不是 DSH 配对链接。',
    noCamera: '此浏览器无法打开摄像头，请改为粘贴配对链接。',
    cameraDenied: '没有摄像头权限。请在浏览器设置中允许，或改为粘贴配对链接。',
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
    state_connected: '已连接',
    state_connecting: '正在连接…',
    state_retrying: '无法连接',
    state_rejected: '已不再配对',
    noWorker: '此浏览器无法运行启动页：Service Worker 不可用。请使用 HTTPS 和较新的浏览器；无痕模式可能会禁用它。',
    noCrypto: '此页面必须通过 HTTPS 打开。',
    expired: '配对码已过期，请在 DSH 设置中重新生成。',
  },
}
const LANG = /^zh\b/i.test(navigator.language ?? '') ? 'zh' : 'en'
const encoder = new TextEncoder()
const APP_SCOPE = new URL('./app/', location.href)
const CARRIER = '<script>(function(){try{var b=window.parent!==window&&window.parent.__DSH_REMOTE__;if(b){window.__DSH_TRANSPORT__={createWebSocket:function(u){return b.openWebSocket(u)}};window.__DSH_FILE_UPLOAD__={fetch:function(u,i){return b.upload(new URL(String(u),document.baseURI).href,i||{})}}}}catch(e){}})();</script>'
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
  for (const element of document.querySelectorAll('[data-placeholder]')) element.placeholder = t(element.dataset.placeholder)
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
      const html = await new Response(body).text()
      session.bootPreference = bootPreference(html)
      body = streamOf(encoder.encode(injectCarrier(html)))
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

/** Path on the DSH host of an absolute URL in the embedded page. */
function hostPath(url) {
  const target = new URL(url)
  const prefix = `${APP_SCOPE.pathname}${workerClientId}`
  const pathname = target.pathname.startsWith(`${prefix}/`) ? target.pathname.slice(prefix.length) : target.pathname
  return `${pathname}${target.search}`
}

/** Transports the carrier script in the embedded page calls. */
window.__DSH_REMOTE__ = {
  openWebSocket(url) {
    const session = current
    if (session === undefined) throw new Error('not connected')
    return session.remote.openWebSocket(url, hostPath(url))
  },

  /**
   * DSH's file upload carrier (`__DSH_FILE_UPLOAD__`). By default DSH posts an upload from a Blob
   * Worker, which the service worker then forwards; on iOS that upload fails. This reads the body
   * in the page and sends it through the tunnel directly.
   */
  async upload(url, init) {
    const session = current
    if (session === undefined) throw new Error('not connected')
    const body = init.body == null ? null : new Uint8Array(await new Response(init.body).arrayBuffer())
    const headers = [...new Headers(init.headers)].filter(([name]) => !DROPPED_REQUEST_HEADERS.has(name))
    headers.push(['accept-encoding', 'identity'])
    const response = await session.remote.request({ method: init.method ?? 'POST', path: hostPath(url), headers, body }, init.signal)
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers.filter(([name]) => !DROPPED_RESPONSE_HEADERS.has(name)),
    })
  },
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/** @type {{ host: object, remote: RemoteHost } | undefined} */
let current
let chipTimer
const QUIET_MS = 2000

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
  setChrome(undefined)
  void renderHosts()
}

// ---------------------------------------------------------------------------
// Window chrome
// ---------------------------------------------------------------------------

// A home-screen web app paints its status bar with theme-color. While a DSH is shown, the launcher
// (status bar, background, chip) follows that DSH's theme, which DSH settings can fix regardless of
// the phone's appearance; the home page follows the phone.
const SYSTEM_DARK = matchMedia('(prefers-color-scheme: dark)')
const CHROME_KEY = 'dsh-remote:chrome:'
const REVEAL_LIMIT_MS = 20_000
const SETTLE_MS = 300
let themeMeta
/** @type {{ color: string, dark: boolean } | undefined} */
let shownChrome

function applyChrome() {
  if (themeMeta === undefined) {
    // One meta whose content changes: the page's media-scoped pair can only follow the phone.
    for (const meta of document.querySelectorAll('meta[name="theme-color"]')) meta.remove()
    themeMeta = document.createElement('meta')
    themeMeta.name = 'theme-color'
    document.head.append(themeMeta)
  }
  const root = document.documentElement
  if (shownChrome === undefined) {
    delete root.dataset.theme
    root.style.removeProperty('--bg')
  } else {
    root.dataset.theme = shownChrome.dark ? 'dark' : 'light'
    root.style.setProperty('--bg', shownChrome.color)
  }
  themeMeta.content = getComputedStyle(root).getPropertyValue('--bg').trim()
}

function setChrome(chrome) {
  shownChrome = chrome
  applyChrome()
}

/** The chrome a host's page had last time, so a reopened DSH does not flash the phone's theme. */
function savedChrome(serverId) {
  try {
    const saved = JSON.parse(localStorage.getItem(CHROME_KEY + serverId) ?? 'null')
    return typeof saved?.color === 'string' && typeof saved.dark === 'boolean' ? saved : undefined
  } catch {
    return undefined
  }
}

/** The opaque background at the top edge of the DSH page, and whether its theme is dark. */
function readChrome(frame) {
  let doc
  try {
    doc = frame.contentDocument
  } catch {
    return undefined
  }
  const win = doc?.defaultView
  if (!doc?.body || !win) return undefined
  const opaque = (element) => {
    const color = win.getComputedStyle(element).backgroundColor
    if (!color || color === 'transparent') return undefined
    const alpha = /^rgba\([^)]*,\s*([\d.]+)\)$/.exec(color)
    return alpha !== null && Number(alpha[1]) < 1 ? undefined : color
  }
  let color
  for (let element = doc.elementFromPoint(win.innerWidth / 2, 0); element && color === undefined; element = element.parentElement) color = opaque(element)
  color ??= opaque(doc.body) ?? opaque(doc.documentElement)
  if (color === undefined) return undefined
  // Dark by the color itself; a color the browser reports in another notation falls back to
  // DSH's dark-theme mark on the body.
  const rgb = /^rgba?\((\d+), (\d+), (\d+)/.exec(color)
  const dark = rgb !== null
    ? 0.2126 * Number(rgb[1]) + 0.7152 * Number(rgb[2]) + 0.0722 * Number(rgb[3]) < 128
    : doc.body.hasAttribute('data-ds-dark-theme')
  return { color, dark }
}

/**
 * Whether the DSH page in the frame may be shown: `show` now, `matched` once that lasts SETTLE_MS,
 * or `wait`. DSH paints its saved theme at once, but its client starts from the phone's appearance
 * until the saved preference arrives through the tunnel, which on a slow link shows as a
 * light-dark flash. The page waits until DSH's client has applied a theme (it then adds its own
 * theme-color meta) and that theme is the one the page booted with.
 */
function pageState(session) {
  let doc
  try {
    doc = session.frame.contentDocument
  } catch {
    return 'show'
  }
  // Not a DSH page (an error page): show it as it is.
  if (doc?.documentElement?.dataset.dsThemeSource === undefined) return 'show'
  if (doc.head?.querySelector('meta[name="theme-color"]') == null) return 'wait'
  const preference = session.bootPreference
  if (preference !== 'light' && preference !== 'dark' && preference !== 'system') return 'matched'
  const dark = preference === 'dark' || (preference === 'system' && doc.defaultView.matchMedia('(prefers-color-scheme: dark)').matches)
  return doc.body?.hasAttribute('data-ds-dark-theme') === dark ? 'matched' : 'wait'
}

/** The theme preference DSH embedded in its page (its boot script), or undefined. */
function bootPreference(html) {
  const match = /\bconst preference = ("(?:[^"\\]|\\.)*")[^]{0,400}?dsThemeSource = preference/.exec(html)
  try {
    return match === null ? undefined : JSON.parse(match[1])
  } catch {
    return undefined
  }
}

/**
 * Follow the page just loaded in the session's frame: show the first page once it settles, then
 * keep the window chrome on the page's theme.
 */
function watchPage(session) {
  session.chromeObserver?.disconnect()
  for (const timer of session.chromeTimers) clearTimeout(timer)
  let scheduled = false
  const reveal = () => {
    session.revealed = true
    session.frame.removeAttribute('data-pending')
  }
  const update = () => {
    scheduled = false
    if (current !== session) return
    if (!session.revealed) {
      const state = pageState(session)
      if (state === 'wait') {
        session.matchedSince = undefined
        return
      }
      if (state === 'matched') {
        session.matchedSince ??= performance.now()
        const left = SETTLE_MS - (performance.now() - session.matchedSince)
        if (left > 0) {
          session.chromeTimers.push(setTimeout(session.updatePage, left + 10))
          return
        }
      }
      reveal()
    }
    const chrome = readChrome(session.frame)
    if (chrome === undefined || (chrome.color === shownChrome?.color && chrome.dark === shownChrome?.dark)) return
    setChrome(chrome)
    try {
      localStorage.setItem(CHROME_KEY + session.host.serverId, JSON.stringify(chrome))
    } catch { /* storage unavailable: the next open starts from the phone's theme */ }
  }
  session.updatePage = () => {
    if (scheduled) return
    scheduled = true
    requestAnimationFrame(update)
  }
  try {
    const doc = session.frame.contentDocument
    if (doc?.body) {
      // DSH applies a theme through attributes of <html> and <body>, and adds its theme-color meta.
      session.chromeObserver = new MutationObserver(session.updatePage)
      session.chromeObserver.observe(doc.documentElement, { attributes: true })
      session.chromeObserver.observe(doc.body, { attributes: true })
      if (doc.head) session.chromeObserver.observe(doc.head, { childList: true })
    }
  } catch { /* not the DSH page: an error page of the service worker */ }
  // DSH lays out its header after load; read again once it has rendered. A page whose theme never
  // matches what it booted with (the preference changed meanwhile) is shown after the last one.
  session.chromeTimers = [0, 1000, 3000].map((delay) => setTimeout(session.updatePage, delay))
  session.chromeTimers.push(setTimeout(() => {
    if (session.revealed || current !== session) return
    reveal()
    session.updatePage()
  }, REVEAL_LIMIT_MS))
}

/**
 * Status chip over the DSH page. It shows while the tunnel is not connected and briefly when the
 * tunnel comes back; a connected session puts it away with `restChip`.
 */
function setChip(state, text) {
  const chip = $('chip')
  chip.hidden = false
  chip.dataset.state = state
  delete chip.dataset.collapsed
  chip.querySelector('.text').textContent = text
  chip.querySelector('.text').hidden = false
  $('chip-leave').hidden = false
  $('chip-retry').hidden = state !== 'retrying' && state !== 'connecting'
  clearTimeout(chipTimer)
}

/**
 * Put away the chip of a connected session, now or after `delay` ms. The DSH page's own device
 * button replaces it; a DSH without that button keeps a dot, the only way back to the launcher.
 */
function restChip(delay = 0) {
  clearTimeout(chipTimer)
  if (delay > 0) {
    chipTimer = setTimeout(() => { restChip() }, delay)
    return
  }
  const chip = $('chip')
  if (chip.dataset.state !== 'connected') return
  if (current?.bridge !== 'none') {
    chip.hidden = true
    return
  }
  chip.hidden = false
  chip.dataset.collapsed = ''
  chip.querySelector('.text').hidden = true
  $('chip-leave').hidden = true
  $('chip-retry').hidden = true
}

function leave() {
  closeSession()
  localStorage.removeItem('dsh-remote:last')
  showHome()
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
  const label = hostLabel(host)
  const remote = new RemoteHost({
    relayUrl: host.relayUrl,
    serverId: host.serverId,
    device: { privateKey: host.privateKey, publicJwk: host.publicJwk },
    deviceName: host.deviceName,
    onstatus: (status) => {
      if (current?.remote !== remote) return
      session.state = ['connected', 'rejected', 'retrying'].includes(status.state) ? status.state : 'connecting'
      void sendContext(session)
      if (status.state === 'connected') {
        clearTimeout(session.quietTimer)
        session.quietTimer = undefined
        setChip('connected', t('connected', { host: label }))
        if (!session.loaded) {
          // The first connection shows as the page itself.
          session.loaded = true
          frame.src = `${APP_SCOPE.href}${token}/`
          restChip()
        } else if (session.troubled) {
          restChip(2500)
        } else {
          restChip()
        }
        session.troubled = false
        return
      }
      if (session.loaded && status.state === 'connecting' && !session.troubled) {
        // A tunnel that drops and returns at once, as when the phone wakes, is not news.
        session.quietTimer ??= setTimeout(() => {
          session.quietTimer = undefined
          if (current === session && session.state !== 'connected') showTrouble(remote.status)
        }, QUIET_MS)
        return
      }
      showTrouble(status)
    },
  })
  const showTrouble = (status) => {
    session.troubled = session.loaded
    if (status.state === 'rejected') setChip('rejected', status.code === 'unknown-device' ? t('rejected', { host: label }) : t('failed', { error: status.error }))
    else if (status.state === 'retrying') setChip('retrying', t('retrying', { host: label, error: status.error }))
    else setChip('connecting', t('connecting', { host: label }))
  }
  const frame = document.createElement('iframe')
  frame.title = label
  frame.allow = 'clipboard-read; clipboard-write; microphone; fullscreen'
  // Hidden by opacity, not visibility: a transparent frame keeps painting, so it has its content
  // ready when it fades in; a visibility-hidden frame may show blank for a moment first.
  frame.dataset.pending = ''
  frame.addEventListener('load', () => {
    // The frame's first document is about:blank, from before the tunnel connected.
    if (!session.loaded) return
    watchPage(session)
    clearTimeout(session.bridgeTimer)
    session.bridgeTimer = setTimeout(() => {
      if (session.bridge !== 'waiting') return
      session.bridge = 'none'
      if (current !== session) return
      restChip()
      session.updatePage()
    }, BRIDGE_WAIT_MS)
  })
  // bridge: 'waiting' until the page says hello, 'ready' after, 'none' when it never did.
  const session = {
    host, remote, frame, loaded: false, troubled: false, quietTimer: undefined, state: 'connecting', bridge: 'waiting', bridgeTimer: undefined,
    revealed: false, matchedSince: undefined, bootPreference: undefined, chromeObserver: undefined, chromeTimers: [], updatePage: undefined,
  }
  current = session
  setChrome(savedChrome(host.serverId))
  setChip('connecting', t('connecting', { host: label }))
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
  clearTimeout(session.bridgeTimer)
  clearTimeout(session.quietTimer)
  clearTimeout(chipTimer)
  session.chromeObserver?.disconnect()
  for (const timer of session.chromeTimers) clearTimeout(timer)
  session.remote.stop()
  session.frame.remove()
}

function hostLabel(host) {
  return host.hostName || host.serverId.slice(0, 8)
}

// ---------------------------------------------------------------------------
// Device menu bridge
// ---------------------------------------------------------------------------

// The DSH page in the frame runs the dsh-remote-relay client plugin. Embedded, it says hello to its
// parent and, once answered, shows its sidebar device button with a menu built from our rows. This
// window answers as a DSH that shows another device would, except that it sends no local row: the
// menu lists the DSHs paired in this browser and "Add device", which opens the launcher's add card.
// A plugin older than 0.2.4 still draws "This device", which returns to the launcher. The messages
// carry no secrets; only the current frame is heard.
const BRIDGE = 'dsh-remote-relay'
const BRIDGE_VERSION = 1
const BRIDGE_WAIT_MS = 15_000

async function sendContext(session) {
  if (session.bridge !== 'ready') return
  const hosts = (await listHosts()).sort((a, b) => b.pairedAt - a.pairedAt)
  const target = session.frame.contentWindow
  if (current !== session || target === null) return
  const state = session.state
  const tone = state === 'connected' ? 'ok' : state === 'connecting' ? 'warn' : 'error'
  const remotes = hosts.map((host) => {
    const shown = host.serverId === session.host.serverId
    return {
      id: host.serverId,
      name: hostLabel(host),
      meta: shown ? t(`state_${state}`) : '',
      metaTone: shown && tone === 'error' ? 'error' : undefined,
      tone: shown ? tone : undefined,
      current: shown,
      busy: false,
      action: shown && state !== 'connected' ? 'retry' : 'switch',
    }
  })
  target.postMessage({
    channel: BRIDGE,
    v: BRIDGE_VERSION,
    type: 'context',
    id: session.host.serverId,
    name: hostLabel(session.host),
    state,
    shown: true,
    pending: null,
    rows: { local: null, remotes },
    attributes: {},
  }, location.origin)
}

async function onBridgeMessage(event) {
  const session = current
  const data = event.data
  if (session === undefined || event.source !== session.frame.contentWindow || data?.channel !== BRIDGE || data.v !== BRIDGE_VERSION) return
  if (data.type === 'hello') {
    session.updatePage?.()
    if (session.bridge !== 'ready') {
      session.bridge = 'ready'
      if ($('chip').dataset.collapsed !== undefined) restChip()
    }
    await sendContext(session)
  } else if (data.type === 'menu-open') {
    await sendContext(session)
  } else if (data.type === 'local') {
    leave()
  } else if (data.type === 'add') {
    leave()
    $('add-card').scrollIntoView({ block: 'center' })
    $('pair-input').focus()
  } else if (data.type === 'row' && typeof data.id === 'string') {
    if (data.id === session.host.serverId) {
      if (session.state !== 'connected') session.remote.retryNow()
      return
    }
    const host = (await listHosts()).find((candidate) => candidate.serverId === data.id)
    if (host !== undefined && current === session) await openSession(host)
  }
}

/**
 * Show the pairing card for a code, link, or scanned QR text.
 * @param {string} code - pairing code or link.
 * @param {HTMLElement} errorElement - where to report a malformed code.
 * @returns {Promise<boolean>} whether the code was a pairing offer.
 */
async function startPairing(code, errorElement) {
  let pairing
  try {
    pairing = decodePairing(code)
  } catch {
    showError(errorElement, t('invalidCode'))
    return false
  }
  showError(errorElement, '')
  const card = $('pair-card')
  card.hidden = false
  const hostsCard = $('hosts-card')
  const addCard = $('add-card')
  addCard.hidden = true
  hostsCard.hidden = (await listHosts()).length === 0
  $('pair-intro').textContent = t('pairIntro', { host: pairing.hostName || pairing.serverId.slice(0, 8), time: new Date(pairing.expiresAt).toLocaleTimeString() })
  const nameInput = $('device-name')
  nameInput.value = guessDeviceName()
  const confirmButton = $('pair-confirm')
  if (pairing.expiresAt !== 0 && pairing.expiresAt < Date.now()) showError($('pair-error'), t('expired'))
  $('pair-cancel').onclick = () => {
    card.hidden = true
    hostsCard.hidden = false
    addCard.hidden = false
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
      addCard.hidden = false
      $('pair-input').value = ''
      await renderHosts()
      void openSession(host)
    } catch (error) {
      showError($('pair-error'), error instanceof TunnelError && error.code === 'pairing-invalid' ? `${error.message}` : error?.message ?? String(error))
    } finally {
      confirmButton.disabled = false
      confirmButton.textContent = t('pairAction')
    }
  }
  return true
}

// ---------------------------------------------------------------------------
// QR scanning
// ---------------------------------------------------------------------------

let scanning
let jsQRLoading

/** jsQR (Apache-2.0, vendor/jsQR.js) for browsers without a native QR BarcodeDetector, such as Safari. */
function loadJsQR() {
  jsQRLoading ??= new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = new URL(`./vendor/jsQR.js${RELEASE}`, import.meta.url).href
    script.onload = () => { typeof window.jsQR === 'function' ? resolve(window.jsQR) : reject(new Error(t('noCamera'))) }
    script.onerror = () => { jsQRLoading = undefined; reject(new Error(t('noCamera'))) }
    document.head.append(script)
  })
  return jsQRLoading
}

/** @returns {Promise<(video: HTMLVideoElement) => Promise<string | undefined>>} a QR reader for video frames. */
async function createReader() {
  try {
    if ((await window.BarcodeDetector?.getSupportedFormats())?.includes('qr_code')) {
      const detector = new window.BarcodeDetector({ formats: ['qr_code'] })
      return async (video) => (await detector.detect(video))[0]?.rawValue
    }
  } catch { /* fall back to jsQR */ }
  const decode = await loadJsQR()
  const canvas = document.createElement('canvas')
  const context = canvas.getContext('2d', { willReadFrequently: true })
  return async (video) => {
    const scale = Math.min(1, 640 / Math.max(video.videoWidth, video.videoHeight))
    canvas.width = Math.round(video.videoWidth * scale)
    canvas.height = Math.round(video.videoHeight * scale)
    context.drawImage(video, 0, 0, canvas.width, canvas.height)
    const image = context.getImageData(0, 0, canvas.width, canvas.height)
    return decode(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' })?.data
  }
}

function isPairing(text) {
  try {
    decodePairing(text)
    return true
  } catch {
    return false
  }
}

function stopScan() {
  const session = scanning
  scanning = undefined
  if (session === undefined) return
  for (const track of session.stream.getTracks()) track.stop()
  $('scan-video').srcObject = null
  $('scanner').hidden = true
  $('scan').hidden = false
}

async function startScan() {
  const error = $('add-error')
  showError(error, '')
  stopScan()
  let stream
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false })
  } catch (failure) {
    showError(error, failure?.name === 'NotAllowedError' || failure?.name === 'SecurityError' ? t('cameraDenied') : t('noCamera'))
    return
  }
  const session = { stream }
  scanning = session
  const video = $('scan-video')
  video.srcObject = stream
  $('scan').hidden = true
  $('scanner').hidden = false
  try {
    await video.play()
    const read = await createReader()
    while (scanning === session) {
      const text = video.readyState >= 2 && video.videoWidth > 0 ? await read(video) : undefined
      if (scanning !== session) return
      if (text && isPairing(text)) {
        stopScan()
        await startPairing(text, error)
        return
      }
      if (text) showError(error, t('notPairingQr'))
      await new Promise((resolve) => { setTimeout(resolve, 200) })
    }
  } catch (failure) {
    if (scanning !== session) return
    stopScan()
    showError(error, failure?.message ?? String(failure))
  }
}

async function main() {
  applyStaticText()
  applyChrome()
  SYSTEM_DARK.addEventListener('change', applyChrome)
  $('chip-leave').addEventListener('click', leave)
  window.addEventListener('message', (event) => { void onBridgeMessage(event) })
  window.addEventListener('hashchange', () => {
    // A pairing link opened in a tab that already shows the launcher changes only the fragment.
    const code = location.hash.slice(1)
    if (!isPairing(code)) return
    stopScan()
    closeSession()
    showHome()
    void startPairing(code, $('home-error'))
  })
  $('chip-retry').addEventListener('click', () => { current?.remote.retryNow() })
  $('chip').addEventListener('click', (event) => {
    if (event.target.closest('button')) return
    const text = $('chip').querySelector('.text')
    if (!text.hidden) return
    setChip($('chip').dataset.state, text.textContent)
    restChip(3000)
  })
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') current?.remote.retryNow() })
  window.addEventListener('online', () => { current?.remote.retryNow() })
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') stopScan() })
  $('add-form').addEventListener('submit', (event) => {
    event.preventDefault()
    stopScan()
    void startPairing($('pair-input').value, $('add-error'))
  })
  $('pair-input').addEventListener('paste', (event) => {
    // A pasted complete link goes straight to the pairing card.
    const text = event.clipboardData?.getData('text') ?? ''
    if (!text.includes('k=') || !text.includes('s=')) return
    stopScan()
    void startPairing(text, $('add-error'))
  })
  $('scan').hidden = typeof navigator.mediaDevices?.getUserMedia !== 'function'
  $('scan').addEventListener('click', () => { void startScan() })
  $('scan-cancel').addEventListener('click', stopScan)
  if (globalThis.crypto?.subtle === undefined) {
    $('home').hidden = false
    showError($('home-error'), t('noCrypto'))
    return
  }
  showHome()
  const code = location.hash.slice(1)
  if (code.includes('k=') && code.includes('s=')) {
    await startPairing(code, $('home-error'))
    return
  }
  const last = localStorage.getItem('dsh-remote:last')
  if (last !== null) {
    const host = (await listHosts()).find((candidate) => candidate.serverId === last)
    if (host !== undefined) void openSession(host)
  }
}

void main()
