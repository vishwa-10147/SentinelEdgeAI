/* SentinelEdgeAI service worker: shows Web Push notifications (approval requests).
   The notification only opens a page of this console; the Operator signs in there as usual. */
self.addEventListener('push', event => {
  let data = {}
  try { data = event.data ? event.data.json() : {} } catch (_) { data = { body: event.data ? event.data.text() : '' } }
  const url = typeof data.url === 'string' && data.url.startsWith('/') && !data.url.startsWith('//') ? data.url : '/'
  event.waitUntil(self.registration.showNotification(String(data.title || 'SentinelEdgeAI').slice(0, 120), {
    body: String(data.body || '').slice(0, 300),
    tag: data.tag ? String(data.tag).slice(0, 64) : undefined,
    requireInteraction: !!data.require,
    data: { url }
  }))
})

self.addEventListener('notificationclick', event => {
  event.notification.close()
  const url = (event.notification.data && event.notification.data.url) || '/'
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windows => {
    for (const w of windows) {
      if ('focus' in w) { w.navigate(url); return w.focus() }
    }
    return self.clients.openWindow(url)
  }))
})
