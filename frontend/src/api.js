export const api = {
  async get(path) {
    const r = await fetch(path)
    if (!r.ok) throw new Error(`${path}: ${r.status}`)
    const ct = r.headers.get('content-type') || ''
    return ct.includes('application/json') ? r.json() : r.text()
  },
  health: () => api.get('/health'),
  post: (path, body = {}) =>
    fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(async (r) => { const j = await r.json(); if (!r.ok) throw new Error(j.detail || r.status); return j }),
  events: (q = '') => api.get(`/events?limit=1000${q}`),
  gaps: () => api.get('/timeline/gaps'),
  suspicious: () => api.get('/analysis/suspicious'),
  correlations: () => api.get('/analysis/correlations?threshold=0.6'),
  chains: () => api.get('/analysis/chains'),
  graph: () => api.get('/graph'),
  report: () => api.get('/report?case_name=dashboard-case'),
  liveStatus: () => api.get('/live/status'),
  liveStart: (body) =>
    fetch('/live/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }).then(async (r) => { const j = await r.json(); if (!r.ok) throw new Error(j.detail || r.status); return j }),
  pickFolder: (initial) =>
    fetch('/live/pick-folder', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ initial: initial || null }),
    }).then((r) => r.json()).then((j) => j.path),
  liveStop: () => fetch('/live/stop', { method: 'POST' }).then((r) => r.json()),
  loadScenario: (scenario) =>
    fetch('/cases/load-scenario', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    }).then((r) => r.json()),
}
