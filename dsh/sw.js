/*
 * DSH remote launcher service worker.
 *
 * The launcher page embeds the remote DSH Web GUI in an iframe under `app/<launcher-client-id>/`.
 * This worker controls only that scope. It hands every same-origin request of the embedded page to
 * the launcher window named in the path, which carries the request through the encrypted tunnel and
 * streams the answer back over a MessageChannel. WebSockets never reach a service worker; the
 * launcher installs a WebSocket transport into the embedded page instead.
 */
'use strict'

const NULL_BODY = new Set([101, 103, 204, 205, 304])
const OFFLINE_PAGE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>DSH</title><body style="font:15px system-ui;padding:24px">The DSH remote launcher that opened this page is closed. Open the launcher again.</body>'

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting())
})

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim())
})

self.addEventListener('message', (event) => {
  const data = event.data
  if (data && data.type === 'dsh-remote:whoami' && event.source) {
    event.source.postMessage({ type: 'dsh-remote:whoami', nonce: data.nonce, id: event.source.id })
  }
})

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (url.origin !== self.location.origin) return
  event.respondWith(route(event, url))
})

function splitToken(pathname, scopePath) {
  const rest = pathname.slice(scopePath.length)
  const slash = rest.indexOf('/')
  if (slash <= 0) return undefined
  return { token: rest.slice(0, slash), rest: rest.slice(slash) }
}

async function route(event, url) {
  const scopePath = new URL(self.registration.scope).pathname
  let token
  let path
  if (url.pathname.startsWith(scopePath)) {
    const parts = splitToken(url.pathname, scopePath)
    if (parts === undefined) return new Response('Not found', { status: 404 })
    token = parts.token
    path = parts.rest + url.search
  } else {
    // A root-relative request (for example /favicon.svg) from the embedded page.
    const client = event.clientId ? await self.clients.get(event.clientId) : undefined
    const parts = client ? splitToken(new URL(client.url).pathname, scopePath) : undefined
    if (parts === undefined) return fetch(event.request)
    token = parts.token
    path = url.pathname + url.search
  }
  const launcher = await findLauncher(token)
  if (launcher === undefined) {
    return new Response(OFFLINE_PAGE, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8' } })
  }
  return forward(event.request, launcher, token, path)
}

async function findLauncher(token) {
  const direct = await self.clients.get(token)
  if (direct) return direct
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
  return windows.find((client) => client.id === token)
}

async function forward(request, launcher, token, path) {
  const body = request.method === 'GET' || request.method === 'HEAD' ? null : await request.arrayBuffer()
  const channel = new MessageChannel()
  return new Promise((resolve) => {
    let controller
    let answered = false
    channel.port1.onmessage = (event) => {
      const message = event.data
      if (message.type === 'head') {
        answered = true
        const stream = request.method === 'HEAD' || NULL_BODY.has(message.status) ? null : new ReadableStream({
          start(streamController) { controller = streamController },
          cancel() { channel.port1.postMessage({ type: 'cancel' }) },
        })
        try {
          resolve(new Response(stream, { status: message.status, statusText: message.statusText, headers: message.headers }))
        } catch (error) {
          resolve(new Response(`DSH remote: ${error.message}`, { status: 502 }))
          channel.port1.postMessage({ type: 'cancel' })
        }
      } else if (message.type === 'chunk') {
        if (controller) controller.enqueue(new Uint8Array(message.data))
      } else if (message.type === 'end') {
        try { if (controller) controller.close() } catch (_cancelled) { /* the page stopped reading */ }
        channel.port1.close()
      } else if (message.type === 'error') {
        if (!answered) {
          answered = true
          resolve(new Response(`DSH remote: ${message.message}`, { status: message.status || 502, headers: { 'content-type': 'text/plain; charset=utf-8' } }))
        } else if (controller) {
          try { controller.error(new Error(message.message)) } catch (_closed) { /* already closed */ }
        }
        channel.port1.close()
      }
    }
    launcher.postMessage({
      type: 'dsh-remote:fetch',
      token,
      method: request.method,
      path,
      headers: [...request.headers],
      body,
      mode: request.mode,
      destination: request.destination,
    }, body ? [channel.port2, body] : [channel.port2])
  })
}
