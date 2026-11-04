import { useEffect, useMemo, useRef, useState } from 'react'
import ReactFlow, { Background, Controls, MiniMap, Handle, Position, BaseEdge, EdgeLabelRenderer } from 'reactflow'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api } from './api.js'

/* ---------- design tokens (mirror frontend/DESIGN_NOTES.md) ---------- */
const SEV = {
  HIGH: { c: '#ff6b6b', bg: 'rgba(255,107,107,0.12)', bd: 'rgba(255,107,107,0.45)' },
  MEDIUM: { c: '#fbbf24', bg: 'rgba(251,191,36,0.12)', bd: 'rgba(251,191,36,0.45)' },
  LOW: { c: '#60a5db', bg: 'rgba(96,165,219,0.12)', bd: 'rgba(96,165,219,0.45)' },
}
const SEV_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 }
const ETYPE = {
  LOGIN: '#34d399', LOGOFF: '#64748b', FILE_ACCESSED: '#22d3ee',
  FILE_MODIFIED: '#2dd4b5', FILE_COPIED: '#5eead4', FILE_DELETED: '#ff6b6b',
  FILE_CREATED: '#a3e635', PAGE_VISIT: '#a78bfa', FILE_DOWNLOAD: '#38bdf8',
  DEVICE_CONNECTED: '#fb923c', DEVICE_DISCONNECTED: '#94a3b8',
  LOG_CLEARED: '#ef4444', TIMESTAMP_ANOMALY: '#facc15', PROCESS_CREATED: '#f472b6',
}
const ENTITY = { user: '#5b9cff', file: '#2dd4b5', device: '#fb923c', process: '#f472b6' }
const SCENARIOS = [
  ['normal', 'Benign work session — false-positive check'],
  ['deletion', 'Open → copy → delete'],
  ['log_clearing', 'Suspicious activity, then audit-log clear'],
  ['timestamp_manipulation', '$SI older than $FN after file activity'],
  ['combined', 'Access → copy → USB → delete → clear → timestomp'],
  ['legit_suspicious', 'Admin log clear in a documented change window'],
  ['multi_story', 'Three users, three stories, 2 h apart: 3 chains + 2 gaps'],
]
const M = 'font-mono' // every id / hash / timestamp / path / indicator value

const tcolor = (t) => ETYPE[t] || '#8e97ab'
const hhmm = (ts) => (ts || '').slice(11, 16)
const hhmmss = (ts) => (ts || '').slice(11, 19)
const short = (id) => (id || '').slice(0, 8)
const pretty = (t) => (t || '').replace(/_/g, ' ').toLowerCase()

/* ---------- data (bindings unchanged) ---------- */
function useCase(scenario, reloadKey) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  useEffect(() => {
    let live = true
    setErr(null)
    Promise.all([api.events(), api.suspicious(), api.chains(), api.graph(), api.gaps()])
      .then(([events, suspicious, chains, graph, gaps]) => {
        if (live) setData({ events, suspicious, chains, graph, gaps })
      })
      .catch((e) => live && setErr(String(e)))
    return () => { live = false }
  }, [scenario, reloadKey])
  return { data, err }
}

/** Assurance payloads for the current case; `refresh` re-reads them (e.g. after a review). */
function useInsights(data) {
  const [ins, setIns] = useState(null)
  const [rev, setRev] = useState(0)
  useEffect(() => {
    let live = true
    Promise.all(['/analysis/attack', '/analysis/sensitivity', '/analysis/hypotheses', '/analysis/expectations', '/review']
      .map((p) => api.get(p)))
      .then(([attack, sens, hyp, exp, review]) => { if (live) setIns({ attack, sens, hyp, exp, review }) })
      .catch(() => {})
    return () => { live = false }
  }, [data, rev])
  return [ins, () => setRev((r) => r + 1)]
}

/** event_id -> highest severity level that flagged it (from graph node payloads) */
function useFlags(data) {
  return useMemo(() => {
    const m = {}
    data.graph.nodes.forEach((n) => {
      if (n.kind !== 'event' || !n.flagged_by?.length) return
      m[n.id] = n.flagged_by.reduce((a, f) => (SEV_RANK[f.level] > SEV_RANK[a] ? f.level : a), n.flagged_by[0].level)
    })
    return m
  }, [data])
}

function useCountUp(value, ms = 700) {
  const [n, setN] = useState(value)
  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) { setN(value); return }
    let raf, start
    const step = (t) => {
      start ??= t
      const p = Math.min(1, (t - start) / ms)
      setN(value * (1 - Math.pow(1 - p, 3)))
      if (p < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    // rAF is paused in background tabs: guarantee the final value regardless
    const done = setTimeout(() => { cancelAnimationFrame(raf); setN(value) }, ms + 100)
    return () => { cancelAnimationFrame(raf); clearTimeout(done) }
  }, [value, ms])
  return n
}

/* ---------- icons (inline, stroke-based, offline) ---------- */
const ICONS = {
  overview: <><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>,
  timeline: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
  findings: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M12 8v4M12 16h.01" /></>,
  graph: <><circle cx="5" cy="6" r="2.5" /><circle cx="19" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" /><path d="M7.2 7.2l3.6 8.6M16.8 7.2l-3.6 8.6M7.5 6h9" /></>,
  report: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6M8 13h8M8 17h5" /></>,
  events: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>,
  flag: <><path d="M4 22V4M4 4h13l-2 4 2 4H4" /></>,
  layers: <><path d="M12 2l10 5-10 5L2 7z" /><path d="M2 12l10 5 10-5M2 17l10 5 10-5" /></>,
  link: <><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7" /><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7" /></>,
  nodes: <><circle cx="12" cy="12" r="3" /><circle cx="4" cy="4" r="2" /><circle cx="20" cy="4" r="2" /><circle cx="4" cy="20" r="2" /><circle cx="20" cy="20" r="2" /><path d="M5.5 5.5l4.2 4.2M18.5 5.5l-4.2 4.2M5.5 18.5l4.2-4.2M18.5 18.5l-4.2-4.2" /></>,
  edges: <><path d="M7 17L17 7M9 7h8v8" /></>,
  print: <><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" /><rect x="6" y="14" width="12" height="8" rx="1" /></>,
  chevron: <path d="M6 9l6 6 6-6" />,
  play: <path d="M6 4l14 8-14 8z" />,
  refresh: <><path d="M21 12a9 9 0 1 1-2.6-6.4L21 8" /><path d="M21 3v5h-5" /></>,
  warn: <><path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /><path d="M12 9v4M12 17h.01" /></>,
  check: <><circle cx="12" cy="12" r="10" /><path d="M8 12l3 3 5-6" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7" /></>,
  file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></>,
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  assurance: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" /></>,
  lock: <><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></>,
  device: <><rect x="7" y="2" width="10" height="20" rx="2" /><path d="M11 18h2" /></>,
  plug: <><path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0zM12 18v4" /></>,
  camera: <><path d="M3 8a2 2 0 0 1 2-2h2.5l1.5-2h6l1.5 2H19a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><circle cx="12" cy="13" r="3.5" /></>,
  trash: <><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2M6 6l1 14a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-14" /></>,
}
function Icon({ name, size = 16, className = '', stroke = 1.8 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">{ICONS[name]}</svg>
  )
}

/* ---------- primitives ---------- */
function Card({ title, badge, right, children, className = '', bodyClass = 'p-5', style }) {
  return (
    <section className={`tx-panel animate-fade-up ${className}`} style={style}>
      {(title || right) && (
        <header className="flex items-center justify-between gap-3 px-5 pt-4 pb-3 border-b border-white/[0.05]">
          <h2 className="text-[13px] font-semibold tracking-wide text-ink-text flex items-center gap-2.5">
            {badge}{title}
          </h2>
          {right}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

const TIER = {
  Evidence: { cls: 'bg-slate-400/10 text-slate-300 border-slate-400/30', dot: '#94a3b8', note: 'observed' },
  Correlation: { cls: 'bg-blue-500/10 text-blue-300 border-blue-400/35', dot: '#5b9cff', note: 'measured' },
  Hypothesis: { cls: 'bg-amber-500/10 text-amber-300 border-amber-400/35', dot: '#fbbf24', note: 'interpreted + limited' },
}
function TierBadge({ tier }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10.5px] font-medium px-2 py-0.5 rounded-full border ${TIER[tier].cls}`}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: TIER[tier].dot }} />{tier}
    </span>
  )
}

function LevelChip({ level }) {
  const s = SEV[level] || SEV.LOW
  return (
    <span className="inline-flex items-center gap-1 text-[10.5px] font-bold tracking-wider px-2 py-0.5 rounded-md border"
      style={{ color: s.c, background: s.bg, borderColor: s.bd }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.c, boxShadow: `0 0 6px ${s.c}` }} />{level}
    </span>
  )
}

function TypeChip({ type }) {
  const c = tcolor(type)
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10.5px] px-1.5 py-0.5 rounded-md ${M}`}
      style={{ color: c, background: `${c}14`, border: `1px solid ${c}33` }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: c }} />{type}
    </span>
  )
}

function Meter({ value, color = '#5b9cff', className = 'h-1.5' }) {
  return (
    <div className={`flex-1 rounded-full bg-white/[0.06] overflow-hidden ${className}`}>
      <div className="h-full rounded-full transition-[width] duration-700"
        style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%`, background: `linear-gradient(90deg, ${color}99, ${color})`, boxShadow: `0 0 10px ${color}66` }} />
    </div>
  )
}

function Empty({ icon, title, hint, tone = '#5b9cff' }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <div className="w-12 h-12 rounded-2xl flex items-center justify-center mb-3 border"
        style={{ color: tone, background: `${tone}12`, borderColor: `${tone}33` }}><Icon name={icon} size={22} /></div>
      <p className="text-sm text-ink-text font-medium">{title}</p>
      <p className="text-xs text-ink-muted mt-1 max-w-sm leading-relaxed">{hint}</p>
    </div>
  )
}

/* ---------- shell: sidebar + top bar ---------- */
function Logo() {
  return (
    <div className="flex items-center gap-3 px-2">
      <div className="relative w-10 h-10 rounded-xl flex items-center justify-center"
        style={{ background: 'linear-gradient(135deg,#5b9cff,#8b7bff)', boxShadow: '0 8px 24px -6px rgba(91,156,255,0.6)' }}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round">
          <circle cx="12" cy="12" r="8" strokeOpacity=".55" /><circle cx="12" cy="12" r="3.5" />
          <path d="M12 2v4M12 18v4M2 12h4M18 12h4" />
        </svg>
      </div>
      <div>
        <div className="text-[17px] font-extrabold tracking-tight leading-none">TRACE<span className="tx-gradient-text">-X</span></div>
        <div className="text-[10px] text-ink-faint mt-1 tracking-[0.14em] uppercase">Forensic correlation</div>
      </div>
    </div>
  )
}

const NAV = [
  ['Overview', 'overview'], ['Timeline', 'timeline'], ['Findings', 'findings'], ['Graph', 'graph'],
  ['Assurance', 'assurance'], ['Report', 'report'],
]
function Sidebar({ tab, setTab, data }) {
  const counts = data ? {
    Timeline: data.events.length, Findings: data.suspicious.length, Graph: data.graph.nodes.length,
  } : {}
  return (
    <aside className="tx-no-print w-[232px] shrink-0 h-screen sticky top-0 flex flex-col gap-6 py-6 px-4 border-r border-white/[0.05] bg-[#080b12]/70 backdrop-blur-xl">
      <Logo />
      <nav className="flex flex-col gap-1">
        <div className="text-[10px] uppercase tracking-[0.16em] text-ink-faint px-3 mb-1">Investigate</div>
        {NAV.map(([t, ic]) => {
          const on = tab === t
          return (
            <button key={t} onClick={() => setTab(t)}
              className={`group relative flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] transition-all
                ${on ? 'text-white bg-gradient-to-r from-accent/20 to-accent-2/5' : 'text-ink-muted hover:text-ink-text hover:bg-white/[0.03]'}`}>
              {on && <span className="absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full bg-gradient-to-b from-accent to-accent-2" />}
              <Icon name={ic} size={17} className={on ? 'text-accent' : 'text-ink-faint group-hover:text-ink-muted'} />
              <span className={on ? 'font-semibold' : ''}>{t}</span>
              {counts[t] != null && (
                <span className={`ml-auto text-[10.5px] px-1.5 py-0.5 rounded-md ${M}
                  ${t === 'Findings' && counts[t] > 0 ? 'bg-sev-high/15 text-sev-high' : 'bg-white/[0.05] text-ink-muted'}`}>{counts[t]}</span>
              )}
            </button>
          )
        })}
      </nav>
      <div className="mt-auto tx-inset p-3.5">
        <div className="text-[10px] uppercase tracking-[0.16em] text-ink-faint mb-2.5">Epistemic model</div>
        {Object.keys(TIER).map((t) => (
          <div key={t} className="flex items-center justify-between py-1">
            <TierBadge tier={t} /><span className="text-[10.5px] text-ink-faint">{TIER[t].note}</span>
          </div>
        ))}
        <p className="text-[10.5px] text-ink-faint mt-2.5 leading-relaxed">Every hypothesis ships with what it does <i>not</i> establish.</p>
      </div>
    </aside>
  )
}

function ScenarioMenu({ onLoad, busy, liveRunning, onLiveStart, onLiveStop }) {
  const [open, setOpen] = useState(false)
  const [folder, setFolder] = useState('')
  const [picking, setPicking] = useState(false)
  const [liveErr, setLiveErr] = useState(null)
  const browse = async () => {
    setLiveErr(null); setPicking(true)
    try { const p = await api.pickFolder(folder.trim()); if (p) setFolder(p) } // null = dialog cancelled
    catch (e) { setLiveErr(`Couldn't open the folder picker: ${e.message || e}`) }
    finally { setPicking(false) }
  }
  const ref = useRef(null)
  const start = async (mode, watch) => {
    setLiveErr(null)
    try { await onLiveStart(mode, watch); setOpen(false) } catch (e) { setLiveErr(String(e.message || e)) }
  }
  useEffect(() => {
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((o) => !o)} disabled={busy}
        className="flex items-center gap-2 text-[12.5px] font-medium px-3.5 py-2 rounded-xl text-white transition-all disabled:opacity-60
          bg-gradient-to-r from-accent to-accent-2 shadow-[0_6px_20px_-6px_rgba(91,156,255,0.7)] hover:brightness-110">
        <Icon name={busy ? 'refresh' : 'play'} size={13} className={busy ? 'animate-spin' : ''} />
        {busy ? 'Loading…' : 'Load scenario'}
        <Icon name="chevron" size={13} />
      </button>
      {open && (
        <div className="absolute right-0 mt-2 w-[380px] max-h-[80vh] overflow-auto z-30 tx-panel p-1.5 animate-fade-up !bg-none !bg-[#0e121b]/95">
          {liveRunning && (
            <button onClick={() => { setOpen(false); onLiveStop() }}
              className="w-full flex items-center gap-2 text-left px-3 py-2.5 mb-1 rounded-lg border border-sev-high/30 bg-sev-high/10 text-sev-high hover:bg-sev-high/15 transition-colors text-[12.5px] font-medium">
              <span className="w-2 h-2 rounded-sm bg-sev-high" />Stop live session
            </button>
          )}
          <div className="px-3 pt-2 pb-1.5 text-[10px] uppercase tracking-[0.16em] text-ink-faint">Synthetic ground-truth scenarios</div>
          {SCENARIOS.map(([s, d]) => (
            <button key={s} onClick={() => { setOpen(false); onLoad(s) }}
              className="w-full text-left px-3 py-2.5 rounded-lg hover:bg-white/[0.05] transition-colors">
              <div className={`text-[12.5px] text-ink-text ${M}`}>{s}</div>
              <div className="text-[11px] text-ink-muted mt-0.5">{d}</div>
            </button>
          ))}

          <div className="px-3 pt-3 pb-1.5 mt-1 border-t border-white/[0.05] text-[10px] uppercase tracking-[0.16em] text-ink-faint flex items-center gap-2">
            Dynamic ground-truth scenarios
            <span className="px-1.5 py-px rounded bg-accent-cyan/15 text-accent-cyan normal-case tracking-normal text-[9.5px] font-semibold">real time</span>
          </div>
          <button onClick={() => start('scripted')}
            className="w-full text-left px-3 py-2.5 rounded-lg hover:bg-accent-cyan/[0.07] transition-colors">
            <div className={`text-[12.5px] text-ink-text ${M}`}>live_copy_to_usb</div>
            <div className="text-[11px] text-ink-muted mt-0.5">Acted out for real in a sandbox while TRACE-X watches: edit → create → copy to stick → delete.</div>
            <div className="text-[10.5px] text-accent-cyan/80 mt-1">Expected: evidence_deletion HIGH · 1 deletion chain</div>
          </button>

          <div className="px-3 pt-3 pb-1.5 mt-1 border-t border-white/[0.05] text-[10px] uppercase tracking-[0.16em] text-ink-faint">Live monitor · no ground truth</div>
          <div className="px-3 pb-2.5">
            <div className="text-[11px] text-ink-muted mb-2">Watch a folder on this PC (plus any USB stick) and analyse activity as it happens.</div>
            <div className="flex gap-1.5">
              <input value={folder} onChange={(e) => setFolder(e.target.value)} placeholder="Browse, or paste a folder path"
                title={folder} className={`flex-1 min-w-0 text-[11.5px] px-2.5 py-1.5 rounded-lg bg-black/30 border border-white/[0.08] text-ink-text placeholder:text-ink-faint focus:outline-none focus:border-accent/60 ${M}`} />
              <button onClick={browse} disabled={picking} title="Choose a folder with the Windows folder picker"
                className="flex items-center gap-1.5 text-[11.5px] px-2.5 py-1.5 rounded-lg bg-white/[0.04] border border-white/[0.1] text-ink-text hover:bg-white/[0.08] hover:border-accent/40 disabled:opacity-60 transition-colors">
                <Icon name={picking ? 'refresh' : 'folder'} size={13} className={picking ? 'animate-spin' : ''} />Browse
              </button>
              <button onClick={() => start('monitor', [folder])} disabled={!folder.trim() || picking}
                className="text-[11.5px] px-3 py-1.5 rounded-lg bg-accent/15 border border-accent/40 text-blue-200 hover:bg-accent/25 disabled:opacity-40 transition-colors">Start</button>
            </div>
            {picking && <div className="text-[10.5px] text-accent-cyan mt-1.5">Choose a folder in the window that just opened (it may be behind the browser)…</div>}
          </div>
          {liveErr && <div className="mx-3 mb-2 text-[11px] text-sev-high">{liveErr}</div>}
          <div className="px-3 py-2 text-[10.5px] text-ink-faint border-t border-white/[0.05] mt-1">
            via <code className={M}>POST /cases/load-scenario</code> · <code className={M}>POST /live/start</code>
          </div>
        </div>
      )}
    </div>
  )
}

function TopBar({ tab, caseName, err, data, onLoad, onRefresh, rerunning, busy, live, setLive, updated, liveRunning, onLiveStart, onLiveStop }) {
  const ok = data && !err
  const online = ok && live
  return (
    <div className="tx-no-print flex items-center gap-4 mb-6">
      <div>
        <div className="flex items-center gap-2 text-[11px] text-ink-faint">
          <span>Case</span><span>/</span><span className={`text-ink-muted ${M}`}>{caseName}</span>
        </div>
        <h1 className="text-[24px] font-bold tracking-tight mt-0.5">{tab}</h1>
      </div>
      <div className="ml-auto flex items-center gap-2.5">
        <span className={`relative overflow-hidden flex items-center gap-2 text-[11.5px] px-3 py-1.5 rounded-full border transition-all duration-500
          ${online ? 'border-accent-cyan/50 bg-accent-cyan/[0.08] text-accent-cyan shadow-[0_0_18px_-4px_rgba(56,214,245,0.55)]'
            : ok ? 'border-emerald-400/25 bg-emerald-400/[0.06] text-emerald-300'
              : err ? 'border-sev-high/30 bg-sev-high/[0.06] text-sev-high' : 'border-white/10 text-ink-muted'}`}>
          {online && <span className="absolute inset-y-0 left-0 w-1/3 pointer-events-none animate-sweep bg-gradient-to-r from-transparent via-accent-cyan/25 to-transparent" />}
          <span className="relative flex w-2 h-2">
            {ok && <span className={`absolute inset-0 rounded-full animate-ping2 ${online ? 'bg-accent-cyan' : 'bg-emerald-400'}`} />}
            <span className={`relative w-2 h-2 rounded-full transition-colors duration-500 ${online ? 'bg-accent-cyan' : ok ? 'bg-emerald-400' : err ? 'bg-sev-high' : 'bg-ink-faint'}`} />
          </span>
          {/* keyed so the words re-enter with the swap animation whenever the mode flips */}
          <span key={online ? 'online' : ok ? 'offline' : err ? 'err' : 'wait'} className="relative animate-pill-swap">
            {ok ? (online ? 'Engine online · Online mode' : 'Engine online · offline mode') : err ? 'API unreachable' : 'Connecting…'}
          </span>
        </span>
        <button onClick={() => setLive((v) => !v)} title={live ? 'Stop auto-refresh' : 'Re-run analysis every 3 seconds'}
          className={`flex items-center gap-2 text-[11.5px] px-3 py-1.5 rounded-full border transition-colors
            ${live ? 'border-sev-high/40 bg-sev-high/10 text-sev-high' : 'border-white/[0.08] bg-white/[0.03] text-ink-muted hover:text-ink-text'}`}>
          <span className="relative flex w-2 h-2">
            {live && <span className="absolute inset-0 rounded-full bg-sev-high animate-ping2" />}
            <span className={`relative w-2 h-2 rounded-full ${live ? 'bg-sev-high' : 'bg-ink-faint'}`} />
          </span>
          {live ? `Live · ${updated ? updated.toLocaleTimeString([], { hour12: false }) : '…'}` : 'Live off'}
        </button>
        <button onClick={onRefresh} disabled={rerunning} title="Re-run analysis"
          className={`w-9 h-9 rounded-xl flex items-center justify-center border transition-all duration-300 active:scale-90
            ${rerunning ? 'border-accent-cyan/70 bg-accent-cyan/15 text-accent-cyan shadow-[0_0_22px_rgba(56,214,245,.75)] scale-110'
              : 'border-white/[0.08] bg-white/[0.03] text-ink-muted hover:text-accent-cyan hover:border-accent-cyan/40 hover:shadow-[0_0_14px_rgba(56,214,245,.35)] hover:bg-white/[0.06]'}`}>
          <Icon name="refresh" size={15} className={rerunning ? 'animate-spin' : ''} />
        </button>
        <ScenarioMenu onLoad={onLoad} busy={busy} liveRunning={liveRunning} onLiveStart={onLiveStart} onLiveStop={onLiveStop} />
      </div>
    </div>
  )
}

/* ---------- Overview ---------- */
function StatTile({ icon, value, label, accent, sub, delay = 0 }) {
  const n = useCountUp(value)
  return (
    <div className="tx-panel relative overflow-hidden p-4 animate-fade-up group hover:-translate-y-0.5 transition-transform" style={{ animationDelay: `${delay}ms` }}>
      <div className="absolute -right-6 -top-6 w-24 h-24 rounded-full blur-2xl opacity-25 group-hover:opacity-40 transition-opacity" style={{ background: accent }} />
      <div className="flex items-center justify-between">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center border"
          style={{ color: accent, borderColor: `${accent}40`, background: `${accent}14` }}><Icon name={icon} size={17} /></div>
        {sub && <span className="text-[10.5px] text-ink-faint">{sub}</span>}
      </div>
      <div className={`text-[28px] font-bold leading-none mt-4 ${M}`}>{Math.round(n)}</div>
      <div className="text-[11px] text-ink-muted mt-1.5 uppercase tracking-[0.12em]">{label}</div>
    </div>
  )
}

function Gauge({ value, level }) {
  const v = useCountUp(value, 900)
  const color = level ? SEV[level].c : '#34d399'
  const R = 62, C = 2 * Math.PI * R, ARC = 0.75 // 270° sweep
  return (
    <div className="relative w-[168px] h-[168px] shrink-0">
      <svg viewBox="0 0 160 160" className="w-full h-full -rotate-[225deg]">
        <defs>
          <linearGradient id="gg" x1="0" x2="1" y1="0" y2="1">
            <stop offset="0" stopColor={color} stopOpacity=".55" /><stop offset="1" stopColor={color} />
          </linearGradient>
          <filter id="gglow"><feGaussianBlur stdDeviation="3.5" /></filter>
        </defs>
        <circle cx="80" cy="80" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="11"
          strokeDasharray={`${C * ARC} ${C}`} strokeLinecap="round" />
        <circle cx="80" cy="80" r={R} fill="none" stroke={color} strokeOpacity=".45" strokeWidth="11" filter="url(#gglow)"
          strokeDasharray={`${C * ARC * v} ${C}`} strokeLinecap="round" />
        <circle cx="80" cy="80" r={R} fill="none" stroke="url(#gg)" strokeWidth="11"
          strokeDasharray={`${C * ARC * v} ${C}`} strokeLinecap="round" />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className={`text-[34px] font-bold leading-none ${M}`} style={{ color }}>{v.toFixed(2)}</div>
        <div className="text-[10px] uppercase tracking-[0.16em] text-ink-faint mt-1.5">peak score</div>
        <div className="mt-2">{level ? <LevelChip level={level} /> : <span className="text-[11px] text-emerald-300">no flags</span>}</div>
      </div>
    </div>
  )
}

function ActivityStrip({ data, flags }) {
  const [hover, setHover] = useState(null)
  const bins = useMemo(() => {
    const evs = [...data.events].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
    if (!evs.length) return null
    const ts = evs.map((e) => Date.parse(e.timestamp))
    const t0 = ts[0], t1 = ts[ts.length - 1], N = 32
    const span = Math.max(t1 - t0, 60000)
    const b = Array.from({ length: N }, (_, k) => ({ n: 0, f: 0, evs: [], start: t0 + (span * k) / N, end: t0 + (span * (k + 1)) / N }))
    evs.forEach((e, i) => {
      const k = Math.min(N - 1, Math.floor(((ts[i] - t0) / span) * N))
      b[k].n++; b[k].evs.push(e); if (flags[e.event_id]) b[k].f++
    })
    return { b, N, max: Math.max(...b.map((x) => x.n)), t0: evs[0].timestamp, t1: evs[evs.length - 1].timestamp }
  }, [data, flags])
  if (!bins) return null
  const clock = (ms) => new Date(ms).toISOString().slice(11, 19)
  const hb = hover != null ? bins.b[hover] : null
  return (
    <div>
      <div className="relative">
        <div className="flex items-end gap-[3px] h-14" onMouseLeave={() => setHover(null)}>
          {bins.b.map((x, i) => (
            <div key={i} className="flex-1 h-full flex items-end cursor-default" onMouseEnter={() => setHover(i)}>
              <div className="w-full rounded-t-sm transition-all duration-700"
                style={{
                  height: `${x.n ? 12 + (x.n / bins.max) * 88 : 4}%`,
                  background: x.n ? (x.f ? 'linear-gradient(180deg,#ff6b6b,#ff6b6b55)' : 'linear-gradient(180deg,#5b9cff,#5b9cff40)') : 'rgba(255,255,255,0.05)',
                  boxShadow: x.f ? '0 0 10px rgba(255,107,107,0.45)' : 'none',
                  outline: hover === i ? '1px solid rgba(255,255,255,0.35)' : 'none',
                }} />
            </div>
          ))}
        </div>
        {hb && (
          <div className="absolute bottom-full mb-2 z-10 pointer-events-none tx-panel !bg-none !bg-[#0e121b]/95 px-3 py-2 text-[11px] min-w-[190px] -translate-x-1/2"
            style={{ left: `${Math.min(85, Math.max(15, ((hover + 0.5) / bins.N) * 100))}%` }}>
            {hb.evs.length === 0
              ? <div className={`text-ink-faint ${M}`}>{clock(hb.start)}–{clock(hb.end)} UTC · no events</div>
              : hb.evs.map((e) => (
                <div key={e.event_id} className="flex items-center gap-2 py-0.5">
                  <span className={`text-ink-text ${M}`}>{e.timestamp.slice(11, 19)}</span>
                  <span className={`${M}`} style={{ color: tcolor(e.event_type) }}>{e.raw_metadata?.renamed_from ? 'FILE_RENAMED' : e.event_type}</span>
                  {flags[e.event_id] && <span className="ml-auto"><LevelChip level={flags[e.event_id]} /></span>}
                </div>
              ))}
          </div>
        )}
      </div>
      <div className={`flex justify-between text-[10px] text-ink-faint mt-1.5 ${M}`}>
        <span>{bins.t0.replace('T', ' ').slice(0, 16)}</span><span>{bins.t1.replace('T', ' ').slice(0, 16)}</span>
      </div>
    </div>
  )
}

function ChainFlow({ chain, events, flags }) {
  const byId = useMemo(() => Object.fromEntries(events.map((e) => [e.event_id, e])), [events])
  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex items-start min-w-max">
        {chain.event_ids.map((id, i) => {
          const e = byId[id]
          const c = tcolor(e?.event_type)
          const f = flags[id]
          return (
            <div key={id} className="flex items-start">
              <div className="flex flex-col items-center w-[108px]">
                <div className="relative w-9 h-9 rounded-full flex items-center justify-center"
                  style={{ background: `${c}1c`, border: `1.5px solid ${f ? SEV[f].c : c}`, boxShadow: f ? `0 0 14px ${SEV[f].c}88` : `0 0 10px ${c}33` }}>
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: c }} />
                  <span className={`absolute -top-1.5 -right-1.5 text-[9px] w-4 h-4 rounded-full bg-ink-panel2 border border-white/10 flex items-center justify-center text-ink-muted ${M}`}>{i + 1}</span>
                </div>
                <div className={`text-[10px] mt-2 text-center leading-tight ${M}`} style={{ color: c }}>{e?.event_type || short(id)}</div>
                <div className={`text-[10px] text-ink-faint mt-0.5 ${M}`}>{hhmmss(e?.timestamp)}</div>
              </div>
              {i < chain.event_ids.length - 1 && (
                <div className="h-9 flex items-center -mx-[30px] w-[60px]">
                  <div className="h-[2px] w-full rounded-full" style={{ background: `linear-gradient(90deg, ${c}, ${tcolor(byId[chain.event_ids[i + 1]]?.event_type)})`, opacity: 0.55 }} />
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function HypothesisBlock({ hypothesis, limitation }) {
  return (
    <div className="grid md:grid-cols-2 gap-3 mt-4">
      <div className="tx-inset p-3">
        <div className="flex items-center gap-2 mb-1.5"><TierBadge tier="Hypothesis" /></div>
        <p className="text-[12.5px] text-ink-text leading-relaxed">{hypothesis.charAt(0).toUpperCase() + hypothesis.slice(1)}.</p>
      </div>
      <div className="rounded-xl p-3 border border-amber-400/25 bg-amber-400/[0.05]">
        <div className="flex items-center gap-1.5 mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.12em] text-amber-300">
          <Icon name="warn" size={13} />Does not establish
        </div>
        <p className="text-[12px] text-amber-100/70 leading-relaxed italic">{limitation}</p>
      </div>
    </div>
  )
}

function Overview({ data, flags, onLoad, goto }) {
  const { events, suspicious, chains, graph } = data
  const byLevel = useMemo(() => {
    const m = { HIGH: 0, MEDIUM: 0, LOW: 0 }
    suspicious.forEach((s) => { m[s.level] = (m[s.level] || 0) + 1 })
    return m
  }, [suspicious])
  const top = useMemo(() => [...suspicious].sort((a, b) => b.suspicion_score - a.suspicion_score), [suspicious])
  const peak = top[0]
  const total = Math.max(1, suspicious.length)
  return (
    <div className="space-y-5">
      <div className="grid gap-5 grid-cols-12">
        <Card className="col-span-12 xl:col-span-5 relative overflow-hidden" bodyClass="p-6">
          <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(420px 220px at 20% 30%, ${(peak ? SEV[peak.level].c : '#34d399')}18, transparent 70%)` }} />
          <div className="relative flex items-center gap-6">
            <Gauge value={peak ? peak.suspicion_score : 0} level={peak?.level} />
            <div className="min-w-0">
              <div className="text-[10.5px] uppercase tracking-[0.16em] text-ink-faint">Case posture</div>
              <div className="text-[19px] font-semibold leading-snug mt-1.5">
                {peak
                  ? <>{byLevel.HIGH > 0 ? <span style={{ color: SEV.HIGH.c }}>{byLevel.HIGH} high-severity</span> : `${suspicious.length}`} finding{(byLevel.HIGH || suspicious.length) === 1 ? '' : 's'}{chains.length > 0 && <>, {chains.length} hypothesis chain{chains.length === 1 ? '' : 's'}</>}</>
                  : 'No anti-forensic rule fired'}
              </div>
              <p className="text-[12px] text-ink-muted mt-2 leading-relaxed">
                {peak ? <>Strongest signal: <span className={`text-ink-text ${M}`}>{peak.rule_name}</span> on <span className={`text-ink-text ${M} break-all`}>{peak.object || peak.user || '—'}</span>.</> : 'Absence of findings is not proof of absence of activity.'}
              </p>
              <p className="text-[10.5px] text-ink-faint mt-3 flex items-center gap-1.5"><Icon name="warn" size={12} />Scores are measured indicators, not verdicts.</p>
            </div>
          </div>
        </Card>
        <div className="col-span-12 xl:col-span-7 grid gap-4 grid-cols-3">
          <StatTile icon="events" value={events.length} label="events analysed" accent="#5b9cff" delay={0} />
          <StatTile icon="flag" value={suspicious.length} label="suspicious events" accent="#ff6b6b" delay={40} />
          <StatTile icon="layers" value={new Set(suspicious.map((s) => s.rule_name)).size} label="rule families hit" sub="of 5" accent="#fbbf24" delay={80} />
          <StatTile icon="link" value={chains.length} label="correlated chains" accent="#38d6f5" delay={120} />
          <StatTile icon="nodes" value={graph.nodes.length} label="graph nodes" accent="#8b7bff" delay={160} />
          <StatTile icon="edges" value={graph.edges.length} label="graph edges" accent="#34d399" delay={200} />
        </div>
      </div>

      <div className="grid gap-5 grid-cols-12">
        <Card className="col-span-12 lg:col-span-7" title="Activity over case window" badge={<TierBadge tier="Evidence" />}
          right={<button onClick={() => goto('Timeline')} className="text-[11.5px] text-accent hover:underline">Open timeline →</button>}>
          <ActivityStrip data={data} flags={flags} />
          <div className="flex items-center gap-4 mt-3 text-[10.5px] text-ink-faint">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-accent" />events</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm bg-sev-high" />bin contains a flagged event</span>
          </div>
        </Card>
        <Card className="col-span-12 lg:col-span-5" title="Severity breakdown" badge={<TierBadge tier="Evidence" />}>
          <div className="flex h-3 rounded-full overflow-hidden bg-white/[0.05] mb-4">
            {['HIGH', 'MEDIUM', 'LOW'].map((l) => byLevel[l] > 0 && (
              <div key={l} style={{ width: `${(byLevel[l] / total) * 100}%`, background: SEV[l].c, boxShadow: `0 0 12px ${SEV[l].c}88` }} />
            ))}
          </div>
          {['HIGH', 'MEDIUM', 'LOW'].map((l) => (
            <div key={l} className="flex items-center gap-3 mb-2.5 last:mb-0">
              <span className="w-[74px]"><LevelChip level={l} /></span>
              <Meter value={byLevel[l] / total} color={SEV[l].c} />
              <span className={`text-xs w-6 text-right ${M}`}>{byLevel[l]}</span>
            </div>
          ))}
        </Card>
      </div>

      <div className="grid gap-5 grid-cols-12">
        <Card className="col-span-12 lg:col-span-5" title="Top findings" badge={<TierBadge tier="Correlation" />}
          right={<button onClick={() => goto('Findings')} className="text-[11.5px] text-accent hover:underline">All findings →</button>}>
          {top.length === 0 && <Empty icon="check" tone="#34d399" title="No suspicious events" hint="No anti-forensic rule fired on this case." />}
          <div className="space-y-2">
            {top.slice(0, 4).map((s) => (
              <div key={s.finding_id} className="tx-inset px-3 py-2.5 flex items-center gap-3 hover:bg-white/[0.04] transition-colors">
                <span className="w-1 self-stretch rounded-full" style={{ background: SEV[s.level].c }} />
                <div className="min-w-0 flex-1">
                  <div className={`text-[12.5px] text-ink-text ${M}`}>{s.rule_name}</div>
                  <div className={`text-[11px] text-ink-faint truncate ${M}`}>{s.object || s.user || '—'}</div>
                </div>
                <div className="text-right">
                  <div className={`text-[15px] font-semibold ${M}`} style={{ color: SEV[s.level].c }}>{s.suspicion_score.toFixed(2)}</div>
                  <div className="text-[9.5px] text-ink-faint uppercase tracking-wider">{s.level}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
        <Card className="col-span-12 lg:col-span-7" title="Chain spotlight" badge={<TierBadge tier="Hypothesis" />}
          right={chains[0] && <span className={`text-[11px] text-ink-faint ${M}`}>mean edge {chains[0].mean_score.toFixed(2)}</span>}>
          {chains.length === 0
            ? <Empty icon="link" title="No chains" hint="No correlated sequence met the chain threshold — no hypotheses offered." />
            : (
              <>
                <div className="text-[15px] font-semibold mb-4">{chains[0].label}</div>
                <ChainFlow chain={chains[0]} events={events} flags={flags} />
                <HypothesisBlock hypothesis={chains[0].hypothesis} limitation={chains[0].limitation} />
              </>
            )}
        </Card>
      </div>

      <div className="tx-inset p-4 flex items-center gap-4">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center bg-accent/10 border border-accent/30 text-accent"><Icon name="play" size={14} /></div>
        <div className="flex-1">
          <div className="text-[13px] font-medium">Try another scenario</div>
          <div className="text-[11.5px] text-ink-muted">Synthetic cases with machine-readable ground truth.</div>
        </div>
        <div className="flex flex-wrap gap-1.5 justify-end">
          {SCENARIOS.map(([s]) => (
            <button key={s} onClick={() => onLoad(s)}
              className={`text-[11px] px-2.5 py-1.5 rounded-lg border border-white/[0.08] bg-white/[0.02] text-ink-muted hover:text-ink-text hover:border-accent/50 hover:bg-accent/10 transition-colors ${M}`}>{s}</button>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ---------- Timeline (custom SVG lanes) ---------- */
function LaneTimeline({ data, flags, sel, onSel }) {
  const [hover, setHover] = useState(null)
  const W = 1100, LH = 38, PADL = 170, PADR = 24, TOP = 30
  const geo = useMemo(() => {
    const evs = [...data.events].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
    if (!evs.length) return null
    const t0 = Date.parse(evs[0].timestamp), t1 = Date.parse(evs[evs.length - 1].timestamp)
    const span = Math.max(t1 - t0, 60000)
    const lanes = [...new Set(evs.map((e) => e.event_type))].sort()
    const xt = (ms) => PADL + ((ms - t0) / span) * (W - PADL - PADR)
    const x = (t) => xt(Date.parse(t))
    const y = (et) => TOP + lanes.indexOf(et) * LH + LH / 2
    const ticks = Array.from({ length: 7 }, (_, i) => t0 + (span * i) / 6)
    const multiDay = span > 86400000
    return { evs, lanes, x, xt, y, t0, t1, ticks, multiDay, H: TOP + lanes.length * LH + 34 }
  }, [data])
  if (!geo) return <Empty icon="timeline" title="No events" hint="Load a scenario to see the timeline." />
  const { evs, lanes, x, xt, y, H, ticks, multiDay } = geo
  const gaps = (data.gaps.gaps || []).filter((g) => Date.parse(g.gap_end) >= geo.t0 && Date.parse(g.gap_start) <= geo.t1)
  const focus = hover || sel
  const hov = focus ? evs.find((e) => e.event_id === focus) : null
  const fmt = (ms) => { const iso = new Date(ms).toISOString(); return multiDay ? iso.slice(5, 16).replace('T', ' ') : iso.slice(11, 16) }
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full select-none" role="img" aria-label="Forensic event timeline">
        <defs>
          <filter id="dotglow" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="4" /></filter>
          <pattern id="hatch" width="6" height="6" patternTransform="rotate(45)" patternUnits="userSpaceOnUse">
            <line x1="0" y1="0" x2="0" y2="6" stroke="rgba(255,107,107,0.18)" strokeWidth="2" />
          </pattern>
        </defs>
        {lanes.map((l, i) => (
          <g key={l}>
            {i % 2 === 0 && <rect x={PADL - 8} y={y(l) - LH / 2} width={W - PADL - PADR + 16} height={LH} fill="rgba(255,255,255,0.018)" rx={6} />}
            <circle cx={14} cy={y(l)} r={4} fill={tcolor(l)} />
            <text x={26} y={y(l) + 4} fontSize={11} fill="#8e97ab" fontFamily="ui-monospace,monospace">{l}</text>
            <line x1={PADL} x2={W - PADR} y1={y(l)} y2={y(l)} stroke="#1a2030" strokeWidth={1} strokeDasharray="2 4" />
          </g>
        ))}
        {ticks.map((t, i) => (
          <g key={i}>
            <line x1={xt(t)} x2={xt(t)} y1={TOP - 6} y2={H - 26} stroke="rgba(255,255,255,0.04)" />
            <text x={xt(t)} y={H - 10} fontSize={10} fill="#5a6377" textAnchor="middle" fontFamily="ui-monospace,monospace">{fmt(t)}</text>
          </g>
        ))}
        {gaps.map((g, i) => (
          <g key={i}>
            <rect x={x(g.gap_start)} y={TOP - 10} width={Math.max(2, x(g.gap_end) - x(g.gap_start))} height={H - TOP - 16}
              fill="url(#hatch)" stroke="rgba(255,107,107,0.4)" strokeDasharray="4 3" rx={4} />
            <text x={x(g.gap_start) + 5} y={TOP - 14} fontSize={10} fill="#ff6b6b" fontFamily="ui-monospace,monospace">gap {g.duration_minutes}m</text>
          </g>
        ))}
        {hov && <line x1={x(hov.timestamp)} x2={x(hov.timestamp)} y1={TOP - 8} y2={H - 26} stroke="rgba(91,156,255,0.5)" strokeDasharray="3 3" />}
        {evs.map((e) => {
          const flag = flags[e.event_id]
          const c = tcolor(e.event_type)
          const cx = x(e.timestamp), cy = y(e.event_type)
          const on = focus === e.event_id
          return (
            <g key={e.event_id} style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHover(e.event_id)} onMouseLeave={() => setHover(null)} onClick={() => onSel(e.event_id)}>
              {(flag || on) && <circle cx={cx} cy={cy} r={on ? 12 : 9} fill={flag ? SEV[flag].c : c} opacity={0.55} filter="url(#dotglow)" />}
              {flag && <circle cx={cx} cy={cy} r={9.5} fill="none" stroke={SEV[flag].c} strokeWidth={1.8} />}
              <circle cx={cx} cy={cy} r={on ? 7 : 5.5} fill={c} stroke="#070910" strokeWidth={1.5} />
              <circle cx={cx} cy={cy} r={14} fill="transparent" />
            </g>
          )
        })}
      </svg>
      {hov && (
        <div className="absolute z-10 pointer-events-none tx-panel !bg-none !bg-[#0e121b]/95 px-3 py-2.5 text-xs w-[260px] -translate-x-1/2"
          style={{ left: `${Math.min(80, Math.max(20, (x(hov.timestamp) / W) * 100))}%`, top: `${((y(hov.event_type) + 18) / H) * 100}%` }}>
          <div className="flex items-center justify-between gap-2"><TypeChip type={hov.event_type} />{flags[hov.event_id] && <LevelChip level={flags[hov.event_id]} />}</div>
          <div className={`text-ink-muted mt-1.5 ${M}`}>{hov.timestamp}</div>
          <div className="text-ink-muted mt-1">user <span className="text-ink-text">{hov.user || '—'}</span> · {hov.device_id || '—'}</div>
          <div className={`text-ink-text mt-0.5 break-all ${M}`}>{hov.object || '—'}</div>
        </div>
      )}
      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-[10.5px] text-ink-faint">
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full border-2 border-sev-high" />ring = flagged (red HIGH · amber MEDIUM · blue LOW)</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm border border-dashed border-sev-high/60 bg-sev-high/10" />hatched band = potentially significant gap</span>
        <span>click a dot to pin its details</span>
      </div>
    </div>
  )
}

function Timeline({ data, flags }) {
  const [sel, setSel] = useState(null)
  const evs = useMemo(() => [...data.events].sort((a, b) => a.timestamp.localeCompare(b.timestamp)), [data])
  const rowRefs = useRef({})
  useEffect(() => { if (sel) rowRefs.current[sel]?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }) }, [sel])
  return (
    <div className="space-y-5">
      <Card title={`Event timeline`} badge={<TierBadge tier="Evidence" />}
        right={<span className={`text-[11px] text-ink-faint ${M}`}>{data.events.length} events · UTC</span>}>
        <LaneTimeline data={data} flags={flags} sel={sel} onSel={(id) => setSel((s) => (s === id ? null : id))} />
      </Card>
      <div className="grid gap-5 grid-cols-12">
        <Card className="col-span-12 xl:col-span-8" title="Event log" badge={<TierBadge tier="Evidence" />} bodyClass="p-0">
          <div className="max-h-[380px] overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#0f131d] z-[1]">
                <tr className="text-left text-ink-faint uppercase tracking-[0.1em] text-[10px]">
                  <th className="px-5 py-2.5 font-medium">Time</th><th className="py-2.5 pr-3 font-medium">Type</th>
                  <th className="py-2.5 pr-3 font-medium">User</th><th className="py-2.5 pr-3 font-medium">Object</th><th className="py-2.5 pr-5 font-medium">Source</th>
                </tr>
              </thead>
              <tbody>
                {evs.map((e) => {
                  const f = flags[e.event_id]
                  return (
                    <tr key={e.event_id} ref={(el) => { rowRefs.current[e.event_id] = el }} onClick={() => setSel(e.event_id)}
                      className={`border-t border-white/[0.04] cursor-pointer transition-colors ${sel === e.event_id ? 'bg-accent/10' : 'hover:bg-white/[0.025]'}`}>
                      <td className={`px-5 py-2 whitespace-nowrap text-ink-muted ${M}`}>
                        <span className="inline-block w-1.5 h-1.5 rounded-full mr-2 align-middle" style={{ background: f ? SEV[f].c : 'transparent', boxShadow: f ? `0 0 6px ${SEV[f].c}` : 'none' }} />
                        {e.timestamp.replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-2 pr-3"><TypeChip type={e.event_type} /></td>
                      <td className="py-2 pr-3 text-ink-text">{e.user || '—'}</td>
                      <td className={`py-2 pr-3 text-ink-muted max-w-[280px] truncate ${M}`} title={e.object || ''}>{e.object || '—'}</td>
                      <td className={`py-2 pr-5 text-ink-faint text-[10.5px] ${M}`}>{e.source}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
        <Card className="col-span-12 xl:col-span-4" title="Potentially significant gaps"
          right={<span className={`text-[11px] text-ink-faint ${M}`}>≥ {data.gaps.threshold_minutes ?? 30} min</span>}>
          {data.gaps.gaps.length === 0
            ? <Empty icon="check" tone="#34d399" title="No silent intervals" hint="No gap over threshold inside active hours." />
            : data.gaps.gaps.map((g, i) => (
              <div key={i} className="rounded-xl p-3 mb-2 last:mb-0 border border-sev-high/20 bg-sev-high/[0.04]">
                <div className={`text-[11.5px] text-ink-text ${M}`}>{g.gap_start.replace('T', ' ').slice(0, 16)} → {g.gap_end.replace('T', ' ').slice(11, 16)}</div>
                <div className="flex items-center justify-between mt-1">
                  <span className={`text-sev-high text-[11px] ${M}`}>{g.duration_minutes} min silent</span>
                  <i className="text-ink-faint text-[10.5px]">review prompt, not a conclusion</i>
                </div>
              </div>
            ))}
        </Card>
      </div>
    </div>
  )
}

/* ---------- Findings ---------- */
function ScoreRing({ score, level, size = 54 }) {
  const c = SEV[level]?.c || SEV.LOW.c
  const R = 22, C = 2 * Math.PI * R
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg viewBox="0 0 54 54" className="w-full h-full -rotate-90">
        <circle cx="27" cy="27" r={R} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="5" />
        <circle cx="27" cy="27" r={R} fill="none" stroke={c} strokeWidth="5" strokeLinecap="round"
          strokeDasharray={`${C * score} ${C}`} style={{ filter: `drop-shadow(0 0 4px ${c})` }} />
      </svg>
      <div className={`absolute inset-0 flex items-center justify-center text-[12px] font-semibold ${M}`} style={{ color: c }}>{score.toFixed(2)}</div>
    </div>
  )
}

function Indicators({ indicators, color, wide = true }) {
  return (
    <div className={`grid gap-x-6 gap-y-2 ${wide ? 'sm:grid-cols-2' : ''}`}>
      {Object.entries(indicators).map(([k, v]) => (
        <div key={k} className="flex items-center gap-2.5">
          <span className={`text-[10.5px] text-ink-muted w-[170px] truncate ${M}`} title={k}>{k}</span>
          {typeof v === 'number' && v >= 0 && v <= 1
            ? <><Meter value={v} color={color} className="h-1" /><span className={`text-[10.5px] w-8 text-right text-ink-text ${M}`}>{v.toFixed(2)}</span></>
            : <span className={`text-[10.5px] text-ink-text ${M}`}>{String(v)}</span>}
        </div>
      ))}
    </div>
  )
}

const COVER = {
  DETECTED: { cls: 'text-emerald-300 bg-emerald-400/10 border-emerald-400/30', label: 'detected' },
  PARTIAL: { cls: 'text-amber-300 bg-amber-400/10 border-amber-400/30', label: 'partial' },
  NOT_COVERED: { cls: 'text-ink-faint bg-white/[0.03] border-white/10', label: 'not covered' },
}
const STATUS = {
  'best supported': 'text-emerald-300 bg-emerald-400/10 border-emerald-400/30',
  tied: 'text-amber-300 bg-amber-400/10 border-amber-400/30',
  possible: 'text-blue-200 bg-accent/10 border-accent/30',
  weakened: 'text-ink-faint bg-white/[0.03] border-white/10',
}
const VERDICT = {
  confirmed: { label: 'Confirm', done: 'Confirmed', cls: 'border-emerald-400/40 bg-emerald-400/10 text-emerald-300' },
  false_alarm: { label: 'False alarm', done: 'False alarm', cls: 'border-sev-high/40 bg-sev-high/10 text-sev-high' },
  unsure: { label: 'Unsure', done: 'Unsure', cls: 'border-amber-400/40 bg-amber-400/10 text-amber-300' },
}

function AttackChips({ techniques }) {
  if (!techniques?.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {techniques.map((t) => (
        <a key={t.id} href={t.url} target="_blank" rel="noreferrer" title={`${t.name} · ${t.tactic}`}
          className={`text-[10.5px] px-1.5 py-0.5 rounded border border-accent-2/40 bg-accent-2/10 text-violet-200 hover:bg-accent-2/20 ${M}`}>
          ATT&CK {t.id}
        </a>
      ))}
    </div>
  )
}

function ReviewBar({ fkey, decision, onSaved }) {
  const [note, setNote] = useState('')
  const [err, setErr] = useState(null)
  const save = async (verdict) => {
    setErr(null)
    try { await api.post('/review', { key: fkey, verdict, note }); setNote(''); onSaved() } catch (e) { setErr(String(e.message || e)) }
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[10px] uppercase tracking-wider text-ink-faint mr-1">Review</span>
      {decision && (
        <span className={`text-[10.5px] px-2 py-0.5 rounded-md border ${VERDICT[decision.verdict].cls}`} title={decision.note || ''}>
          {VERDICT[decision.verdict].done} · {decision.reviewer}{decision.note ? ` · “${decision.note}”` : ''}
        </span>
      )}
      <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note (optional)"
        className="flex-1 min-w-[120px] text-[11px] px-2 py-1 rounded-md bg-black/30 border border-white/[0.08] text-ink-text placeholder:text-ink-faint focus:outline-none focus:border-accent/50" />
      {Object.entries(VERDICT).map(([v, d]) => (
        <button key={v} onClick={() => save(v)}
          className={`text-[10.5px] px-2 py-1 rounded-md border transition-colors hover:brightness-125 ${decision?.verdict === v ? d.cls : 'border-white/10 bg-white/[0.03] text-ink-muted'}`}>{d.label}</button>
      ))}
      {err && <span className="text-[10.5px] text-sev-high">{err}</span>}
    </div>
  )
}

function CompetingHypotheses({ story }) {
  if (!story?.hypotheses?.length) return null
  return (
    <div className="mt-4">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-ink-muted">Competing hypotheses</span>
        <span className="text-[10.5px] text-ink-faint italic">{story.note}</span>
      </div>
      <div className="space-y-1.5">
        {story.hypotheses.map((h) => (
          <div key={h.hypothesis} className="grid grid-cols-[150px_110px_1fr] gap-3 items-start text-[11.5px] tx-inset px-3 py-2">
            <span className="text-ink-text font-medium">{h.hypothesis}</span>
            <span><span className={`text-[10px] px-1.5 py-0.5 rounded border ${STATUS[h.status]}`}>{h.status}</span></span>
            <div className="space-y-0.5">
              {h.supporting.map((x, i) => <div key={`s${i}`} className="text-emerald-300/90">+ {x.text} <span className={`text-ink-faint ${M}`}>{x.events.join(', ')}</span></div>)}
              {h.contradicting.map((x, i) => <div key={`c${i}`} className="text-sev-high/80">− {x.text} <span className={`text-ink-faint ${M}`}>{x.events.join(', ')}</span></div>)}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function FindingExtras({ f, ins, refresh }) {
  const [open, setOpen] = useState(false)
  if (!ins) return null
  const lines = ins.sens?.findings?.[f.key]?.lines || []
  const story = ins.hyp?.find((st) => st.kind === 'finding' && st.id === f.key)
  return (
    <div className="mt-3 pt-3 border-t border-white/[0.05] space-y-2.5">
      <AttackChips techniques={ins.attack?.per_finding?.[f.key]} />
      {lines.length > 0 && (
        <div>
          <button onClick={() => setOpen((o) => !o)} className="text-[11px] text-accent hover:underline flex items-center gap-1">
            <Icon name="chevron" size={12} className={open ? '' : '-rotate-90'} />What would change this conclusion?
          </button>
          {open && (
            <ul className="mt-1.5 space-y-1 text-[11.5px] text-ink-muted list-disc pl-5">
              {lines.map((l, i) => <li key={i}>{l}</li>)}
            </ul>
          )}
        </div>
      )}
      <ReviewBar fkey={f.key} decision={ins.review?.decisions?.[f.key]} onSaved={refresh} />
      <CompetingHypotheses story={story} />
    </div>
  )
}

function MissingEvidence({ gaps }) {
  return (
    <Card title="Missing evidence" badge={<TierBadge tier="Evidence" />}
      right={<span className="text-[11px] text-ink-faint">leads to follow up, not findings</span>}>
      {!gaps ? <div className="tx-skeleton h-10" />
        : gaps.length === 0 ? <Empty icon="check" tone="#34d399" title="Nothing missing" hint="Every expectation checked is met by the evidence." />
          : (
            <div className="space-y-2">
              {gaps.map((g, i) => (
                <div key={i} className="tx-inset px-4 py-3">
                  <div className="flex items-start gap-3">
                    <Icon name="search" size={15} className="text-accent-cyan mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-[12.5px] text-ink-text font-medium">{g.title}</div>
                      <div className="text-[11.5px] text-ink-muted mt-0.5">{g.why_it_matters}</div>
                      <div className="text-[11px] text-ink-faint mt-1">Collect next: <span className="text-ink-muted">{g.collect}</span></div>
                    </div>
                    <div className={`text-[10.5px] text-ink-faint ${M}`}>{g.events.join(', ')}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
    </Card>
  )
}

function Findings({ data, flags }) {
  const sorted = useMemo(() => [...data.suspicious].sort((a, b) => b.suspicion_score - a.suspicion_score), [data])
  const [ins, refresh] = useInsights(data)
  return (
    <div className="space-y-5">
      <Card title="Suspicious events" badge={<TierBadge tier="Evidence" />}
        right={<span className={`text-[11px] text-ink-faint ${M}`}>{sorted.length} finding{sorted.length === 1 ? '' : 's'} · sorted by score</span>}>
        {sorted.length === 0
          ? <Empty icon="check" tone="#34d399" title="No suspicious events" hint="No anti-forensic rule fired on this case. Absence of findings is not proof of absence of activity." />
          : (
            <div className="space-y-3">
              {sorted.map((s, i) => {
                const c = SEV[s.level]?.c || SEV.LOW.c
                return (
                  <div key={s.finding_id} className="tx-inset relative overflow-hidden p-4 animate-fade-up" style={{ animationDelay: `${i * 50}ms` }}>
                    <div className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: c, boxShadow: `0 0 12px ${c}` }} />
                    <div className="flex items-start gap-4">
                      <ScoreRing score={s.suspicion_score} level={s.level} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className={`text-[14px] font-semibold ${M}`}>{s.rule_name}</span>
                          <LevelChip level={s.level} />
                          <span className="text-[11px] text-ink-faint ml-auto">
                            {s.user && <>user <span className="text-ink-muted">{s.user}</span> · </>}{s.device_id || ''}
                          </span>
                        </div>
                        <p className="text-[12.5px] text-ink-muted mt-1.5 leading-relaxed">{s.description}</p>
                        <div className="mt-3 pt-3 border-t border-white/[0.05]"><Indicators indicators={s.indicators} color={c} /></div>
                        <div className={`mt-3 flex flex-wrap items-center gap-1.5 text-[10px] text-ink-faint ${M}`}>
                          <span className="uppercase tracking-wider mr-1">evidence</span>
                          {s.event_ids.map((id) => (
                            <span key={id} className="px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.06]">{short(id)}</span>
                          ))}
                        </div>
                        <FindingExtras f={s} ins={ins} refresh={refresh} />
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
      </Card>
      <Card title="Correlated chains" badge={<TierBadge tier="Hypothesis" />}>
        {data.chains.length === 0 && <Empty icon="link" title="No chains" hint="No correlated sequences met the chain threshold — no hypotheses offered." />}
        <div className="space-y-4">
          {data.chains.map((c) => (
            <div key={c.chain_id} className="tx-inset p-4">
              <div className="flex items-center gap-3 mb-4 flex-wrap">
                <span className="text-[15px] font-semibold">{c.label}</span>
                <span className={`text-[11px] px-2 py-0.5 rounded-md bg-accent/10 border border-accent/25 text-blue-200 ${M}`}>mean edge {c.mean_score.toFixed(2)}</span>
                <span className="ml-auto flex gap-1.5">{c.supporting_rules.map((r) => (
                  <span key={r} className={`text-[10.5px] px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.07] text-ink-muted ${M}`}>{r}</span>
                ))}</span>
              </div>
              <ChainFlow chain={c} events={data.events} flags={flags} />
              <HypothesisBlock hypothesis={c.hypothesis} limitation={c.limitation} />
              {/* chain ids are regenerated per request: match the weighing by label + its events */}
              <CompetingHypotheses story={ins?.hyp?.find((st) => st.kind === 'chain' && st.label === c.label
                && st.event_ids?.length === c.event_ids.length && st.event_ids.every((x) => c.event_ids.includes(x)))} />
            </div>
          ))}
        </div>
      </Card>
      <MissingEvidence gaps={ins?.exp} />
    </div>
  )
}

/* ---------- Assurance ---------- */
const LV_FILL = { HIGH: '#ff6b6b', MEDIUM: '#fbbf24', LOW: '#60a5db' }

function SweepChart({ sweep }) {
  if (!sweep?.rows?.length) return <div className="tx-skeleton h-40" />
  const rows = sweep.rows, W = 660, x0 = 92, cw = (W - x0 - 12) / rows.length
  const maxP = Math.max(1, ...rows.map((r) => r.pairs))
  const di = rows.findIndex((r) => r.threshold === sweep.default)
  return (
    <svg viewBox={`0 0 ${W} 196`} className="w-full" role="img" aria-label="Correlated pairs and chains across chain thresholds">
      <text x="0" y="62" fontSize="11" fill="#8e97ab">correlated</text>
      <text x="0" y="76" fontSize="11" fill="#8e97ab">pairs</text>
      <text x="0" y="146" fontSize="11" fill="#8e97ab">chains</text>
      {rows.map((r, i) => {
        const h = (r.pairs / maxP) * 92, x = x0 + i * cw
        return (
          <g key={r.threshold}>
            <rect x={x + 2} y={110 - h} width={cw - 4} height={h} rx="2" fill={i === di ? '#5b9cff' : 'rgba(142,151,171,0.35)'}>
              <title>{`threshold ${r.threshold.toFixed(2)}: ${r.pairs} pairs, ${r.chains} chain(s)`}</title>
            </rect>
            <rect x={x + 2} y="130" width={cw - 4} height="24" rx="4"
              fill={r.chains ? `rgba(56,214,245,${0.15 + Math.min(r.chains, 3) * 0.12})` : 'rgba(255,255,255,0.03)'}
              stroke={i === di ? '#5b9cff' : 'none'} />
            <text x={x + cw / 2} y="146" fontSize="11" textAnchor="middle" fill={r.chains ? '#e8ecf4' : '#5a6377'}>{r.chains}</text>
            {i % 5 === 0 && <text x={x + cw / 2} y="176" fontSize="10.5" textAnchor="middle" fill="#5a6377">{r.threshold.toFixed(2)}</text>}
          </g>
        )
      })}
      {di >= 0 && <>
        <line x1={x0 + di * cw + cw / 2} x2={x0 + di * cw + cw / 2} y1="10" y2="160" stroke="#5b9cff" strokeDasharray="3 3" />
        <text x={x0 + di * cw + cw / 2 + 5} y="18" fontSize="10.5" fill="#8fc0ff">default {sweep.default.toFixed(2)}</text>
      </>}
      <text x={x0} y="192" fontSize="10.5" fill="#5a6377">chain threshold →</text>
    </svg>
  )
}

function RedTeamRow({ r }) {
  const cells = r.rows
  return (
    <div className="tx-inset px-4 py-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-[12.5px] font-semibold ${M}`}>{r.rule}</span>
        <span className="text-[11px] text-ink-faint">varying: {r.variable}</span>
      </div>
      <div className="flex gap-1 mt-2.5 overflow-x-auto pb-1">
        {cells.map((c, i) => (
          <div key={i} className="flex flex-col items-center min-w-[46px]" title={`${c.value}${r.unit ? ' ' + r.unit : ''}: ${c.detected ? c.level + ' ' + c.score.toFixed(2) : 'missed'}`}>
            <div className="h-6 w-full rounded" style={{ background: c.detected ? LV_FILL[c.level] : 'rgba(255,255,255,0.06)', opacity: c.detected ? 0.8 : 1 }} />
            <span className={`text-[10px] text-ink-faint mt-1 text-center leading-tight ${M}`}>{String(c.value).replace('content activity ', '').replace(' before', '')}</span>
          </div>
        ))}
      </div>
      <div className="text-[11.5px] text-amber-200/80 mt-1.5 flex gap-1.5"><Icon name="warn" size={13} className="shrink-0 mt-px" />{r.evasion}</div>
    </div>
  )
}

const snapTime = (t) => String(t || '').slice(0, 16).replace('T', ' ')

/** Picker over every saved snapshot (newest first) + a two-click "delete all". */
function SnapshotPicker({ snaps, selected, onSelect, onDeleteAll }) {
  const [open, setOpen] = useState(false)
  const [confirm, setConfirm] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) { setOpen(false); setConfirm(false) } }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])
  const cur = snaps.find((s) => s.id === selected) || snaps[0]
  const Counts = ({ s }) => (
    <span className={`text-[10px] text-ink-faint ${M}`}>{s.events} ev · {s.findings} fnd · {s.chains} ch</span>
  )
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((o) => !o)} disabled={!snaps.length}
        className={`group flex items-center gap-2 text-[11.5px] pl-2.5 pr-2 py-1.5 rounded-lg border transition-all disabled:opacity-50
          ${open ? 'border-accent-cyan/60 bg-accent-cyan/10 shadow-[0_0_16px_-4px_rgba(56,214,245,0.6)]' : 'border-white/10 bg-white/[0.03] hover:border-accent-cyan/40'}`}>
        <Icon name="camera" size={13} className="text-accent-cyan" />
        {cur
          ? <><span className="text-ink-text font-medium max-w-[160px] truncate">{cur.case_name || 'unnamed'}</span>
            <span className={`text-ink-faint ${M}`}>{snapTime(cur.taken_at)}</span></>
          : <span className="text-ink-faint">no snapshots yet</span>}
        <span className="text-[10px] px-1.5 rounded-full bg-white/[0.06] text-ink-muted">{snaps.length}</span>
        <Icon name="chevron" size={12} className={`text-ink-muted transition-transform ${open ? '' : 'rotate-180'}`} />
      </button>
      {open && (
        // opens upwards: this card is the last on the page, so a drop-down would run off the bottom
        <div className="absolute right-0 bottom-full mb-2 w-[340px] z-30 tx-panel p-1.5 animate-fade-up !bg-none !bg-[#0e121b]/95">
          <div className="px-2.5 pt-1.5 pb-1 text-[10px] uppercase tracking-[0.16em] text-ink-faint">Compare against</div>
          <div className="max-h-[260px] overflow-auto">
            {snaps.map((s, i) => {
              const on = s.id === cur?.id
              return (
                <button key={s.id} onClick={() => { onSelect(s.id); setOpen(false) }}
                  className={`w-full text-left px-2.5 py-2 rounded-lg transition-colors flex items-center gap-2.5
                    ${on ? 'bg-accent-cyan/10 border border-accent-cyan/30' : 'border border-transparent hover:bg-white/[0.05]'}`}>
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${on ? 'bg-accent-cyan shadow-[0_0_6px_#38d6f5]' : 'bg-white/20'}`} />
                  <span className="flex-1 min-w-0">
                    <span className="flex items-center gap-1.5">
                      <span className="text-[12px] text-ink-text truncate">{s.case_name || 'unnamed'}</span>
                      {i === 0 && <span className="text-[9px] px-1 rounded bg-accent/15 text-blue-200">latest</span>}
                    </span>
                    <span className="flex items-center justify-between gap-2 mt-0.5">
                      <span className={`text-[10.5px] text-ink-muted ${M}`}>{snapTime(s.taken_at)} UTC</span>
                      <Counts s={s} />
                    </span>
                  </span>
                </button>
              )
            })}
          </div>
          <div className="mt-1 pt-1.5 border-t border-white/[0.05] px-1 pb-0.5 flex items-center justify-end gap-1.5">
            {confirm && <span className="text-[10.5px] text-ink-muted mr-auto pl-1.5">Delete all {snaps.length}? This can't be undone.</span>}
            {confirm && <button onClick={() => setConfirm(false)} className="text-[10.5px] px-2 py-1 rounded-md text-ink-muted hover:text-ink-text">Cancel</button>}
            <button onClick={() => { if (!confirm) { setConfirm(true); return } setConfirm(false); setOpen(false); onDeleteAll() }}
              className={`flex items-center gap-1 text-[10.5px] px-2 py-1 rounded-md border transition-colors
                ${confirm ? 'border-sev-high/60 bg-sev-high/20 text-sev-high' : 'border-sev-high/25 bg-sev-high/[0.06] text-sev-high/80 hover:bg-sev-high/15'}`}>
              <Icon name="trash" size={11} />{confirm ? 'Yes, delete all' : 'Delete all snapshots'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function Assurance({ data }) {
  const [ins, refresh] = useInsights(data)
  const [rt, setRt] = useState(null)
  const [court, setCourt] = useState(null)
  const [integ, setInteg] = useState(null)
  const [cmp, setCmp] = useState(null)
  const [snaps, setSnaps] = useState([])
  const [snapSel, setSnapSel] = useState(null) // null = newest
  const [snapName, setSnapName] = useState('')
  const [busy, setBusy] = useState('')
  useEffect(() => { api.get('/analysis/redteam').then(setRt).catch(() => {}); api.get('/assurance/court').then(setCourt).catch(() => {}) }, [])
  const loadInteg = () => api.get('/integrity/verify').then(setInteg).catch(() => {})
  const loadCmp = (sel = snapSel) => Promise.all([
    api.get('/compare/snapshots').then(setSnaps),
    api.get(`/compare${sel ? `?snapshot=${encodeURIComponent(sel)}` : ''}`).then(setCmp),
  ]).catch(() => {})
  const pickSnap = (id) => { setSnapSel(id); loadCmp(id) }
  const deleteSnaps = () => act('del', async () => {
    await fetch('/compare/snapshots', { method: 'DELETE' }); setSnapSel(null); await loadCmp(null)
  })
  useEffect(() => { loadInteg(); loadCmp() }, [data])
  const act = async (name, fn) => { setBusy(name); try { await fn() } finally { setBusy('') } }
  const observed = new Set(ins?.attack?.observed || [])
  const dec = ins?.review?.decisions || {}
  return (
    <div className="space-y-5">
      <div className="grid gap-5 grid-cols-12">
        <Card className="col-span-12 xl:col-span-5" title="Case integrity" badge={<TierBadge tier="Evidence" />}
          right={<div className="flex gap-1.5">
            <button onClick={() => act('verify', loadInteg)} className="text-[11px] px-2.5 py-1 rounded-lg border border-white/10 bg-white/[0.03] text-ink-muted hover:text-ink-text">Verify</button>
            <button onClick={() => act('seal', async () => { await api.post('/integrity/seal'); await loadInteg() })}
              disabled={!!integ?.live_running} title={integ?.live_running ? 'Sealed automatically when the live session stops' : 'Seal the case as it is now'}
              className="text-[11px] px-2.5 py-1 rounded-lg border border-accent/40 bg-accent/10 text-blue-200 hover:bg-accent/20 disabled:opacity-40 flex items-center gap-1"><Icon name="lock" size={12} />Seal now</button>
          </div>}>
          {!integ ? <div className="tx-skeleton h-24" /> : (
            <div>
              <div className={`flex items-center gap-2.5 text-[13px] font-medium ${integ.live_running ? 'text-accent-cyan' : integ.verified ? 'text-emerald-300' : integ.sealed ? 'text-sev-high' : 'text-amber-300'}`}>
                <Icon name={integ.live_running ? 'refresh' : integ.verified ? 'check' : 'warn'} size={18} className={integ.live_running ? 'animate-spin' : ''} />{integ.summary}
              </div>
              <div className="mt-3 text-[11px] text-ink-faint">Case hash · SHA-256 chain over {integ.events} full event records</div>
              <div className={`text-[11.5px] text-ink-text break-all mt-0.5 ${M}`}>{integ.case_hash}</div>
              {integ.sealed && <div className="text-[11px] text-ink-faint mt-2">Sealed {String(integ.sealed_at).slice(0, 16).replace('T', ' ')} UTC · {integ.seal_reason}</div>}
              {integ.verified === false && integ.sealed && (
                <div className={`mt-2 text-[11px] text-sev-high ${M}`}>
                  {['changed', 'added', 'removed'].map((k) => integ[k]?.length ? <div key={k}>{k}: {integ[k].map((x) => x.slice(0, 8)).join(', ')}</div> : null)}
                </div>
              )}
            </div>
          )}
        </Card>
        <Card className="col-span-12 xl:col-span-7" title="Court readiness" badge={<span className="text-[10.5px] px-2 py-0.5 rounded-full border border-white/10 text-ink-muted">Daubert factors</span>}>
          {!court ? <div className="tx-skeleton h-24" /> : (
            <div className="space-y-2">
              {court.map((c) => (
                <div key={c.factor} className="grid grid-cols-[170px_70px_1fr] gap-3 text-[11.5px] items-start">
                  <span className="text-ink-text font-medium">{c.factor}</span>
                  <span><span className={`text-[10px] px-1.5 py-0.5 rounded border ${c.status === 'MET' ? COVER.DETECTED.cls : COVER.PARTIAL.cls}`}>{c.status}</span></span>
                  <span className="text-ink-muted">{c.evidence}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card title="MITRE ATT&CK coverage" right={<span className="text-[11px] text-ink-faint">{observed.size} technique{observed.size === 1 ? '' : 's'} evidenced in this case</span>} bodyClass="p-0">
        <table className="w-full text-[12px]">
          <thead><tr className="text-left text-[10px] uppercase tracking-[0.1em] text-ink-faint">
            <th className="px-5 py-2.5 font-medium">Technique</th><th className="py-2.5 pr-3 font-medium">Tactic</th>
            <th className="py-2.5 pr-3 font-medium">Coverage</th><th className="py-2.5 pr-3 font-medium">This case</th><th className="py-2.5 pr-5 font-medium">How TRACE-X sees it</th>
          </tr></thead>
          <tbody>
            {(ins?.attack?.coverage || []).map((t) => (
              <tr key={t.id} className={`border-t border-white/[0.04] ${observed.has(t.id) ? 'bg-accent-2/[0.06]' : ''}`}>
                <td className="px-5 py-2"><a href={t.url} target="_blank" rel="noreferrer" className={`text-violet-200 hover:underline ${M}`}>{t.id}</a> <span className="text-ink-text">{t.name}</span></td>
                <td className="py-2 pr-3 text-ink-muted">{t.tactic}</td>
                <td className="py-2 pr-3"><span className={`text-[10px] px-1.5 py-0.5 rounded border whitespace-nowrap ${COVER[t.coverage].cls}`}>{COVER[t.coverage].label}</span></td>
                <td className="py-2 pr-3">{observed.has(t.id) ? <span className="text-violet-200 font-semibold">● seen</span> : <span className="text-ink-faint">—</span>}</td>
                <td className="py-2 pr-5 text-ink-muted">{t.how}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <div className="grid gap-5 grid-cols-12">
        <Card className="col-span-12 xl:col-span-7" title="Robustness: does the story survive other thresholds?" badge={<TierBadge tier="Correlation" />}>
          <SweepChart sweep={ins?.sens?.sweep} />
          <div className="mt-2 space-y-1">
            {(ins?.sens?.sweep?.chains || []).map((c) => (
              <div key={c.label + c.events} className="text-[12px] text-ink-muted">
                <span className="text-ink-text font-medium">{c.label}</span> ({c.events} events) holds for thresholds{' '}
                <span className={`text-accent-cyan ${M}`}>{c.holds_from.toFixed(2)}–{c.holds_to.toFixed(2)}</span>
                {c.breaks_at && <> and breaks at <span className={`text-sev-high ${M}`}>{c.breaks_at.toFixed(2)}</span></>}.
              </div>
            ))}
            {ins && !ins.sens?.sweep?.chains?.length && <div className="text-[12px] text-ink-faint">No chain at the default threshold to test.</div>}
          </div>
        </Card>
        <Card className="col-span-12 xl:col-span-5" title="Investigator review" badge={<span className="text-[10.5px] px-2 py-0.5 rounded-full border border-white/10 text-ink-muted">human in the loop</span>}>
          {!ins ? <div className="tx-skeleton h-24" /> : (
            <div className="text-[12px]">
              <div className="flex gap-2 mb-3">
                {Object.entries(VERDICT).map(([v, d]) => (
                  <div key={v} className={`flex-1 rounded-lg border px-3 py-2 ${d.cls}`}>
                    <div className={`text-[20px] font-bold leading-none ${M}`}>{Object.values(dec).filter((x) => x.verdict === v).length}</div>
                    <div className="text-[10.5px] mt-1">{d.done}</div>
                  </div>
                ))}
              </div>
              <div className="text-ink-faint">{data.suspicious.length - Object.keys(dec).filter((k) => data.suspicious.some((f) => f.key === k)).length} finding(s) still unreviewed — review them on the Findings tab.</div>
              {(ins.review.suggestions || []).map((s) => (
                <div key={s.rule} className="mt-2 text-amber-200/80"><span className={M}>{s.rule}</span>: {s.suggest_min_score != null ? `suggest min score ${s.suggest_min_score} — ` : ''}{s.reason}</div>
              ))}
              {ins.review.log?.length > 0 && (
                <div className="mt-3 max-h-36 overflow-auto space-y-1">
                  {[...ins.review.log].reverse().map((e, i) => (
                    <div key={i} className="text-[11px] text-ink-muted"><span className={`text-ink-faint ${M}`}>{e.at.slice(11, 16)}</span> {e.reviewer} marked <span className={M}>{e.rule}</span> {e.verdict.replace('_', ' ')}{e.note ? ` — “${e.note}”` : ''}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title="Red team: where each rule stops detecting" right={<span className="text-[11px] text-ink-faint">measured on synthetic evasion attempts · red HIGH · amber MEDIUM · blue LOW · grey missed</span>}>
        {!rt ? <div className="tx-skeleton h-40" /> : <div className="space-y-2.5">{rt.map((r) => <RedTeamRow key={r.rule} r={r} />)}</div>}
      </Card>

      <Card title="Compare with a snapshot"
        right={<SnapshotPicker snaps={snaps} selected={cmp?.snapshot?.id} onSelect={pickSnap} onDeleteAll={deleteSnaps} />}>
        <div className="flex gap-1.5 mb-3">
          <input value={snapName} onChange={(e) => setSnapName(e.target.value)} placeholder="snapshot name, e.g. before incident"
            className="flex-1 text-[12px] px-2.5 py-1.5 rounded-lg bg-black/30 border border-white/[0.08] text-ink-text placeholder:text-ink-faint focus:outline-none focus:border-accent/50" />
          <button onClick={() => act('snap', async () => { await api.post('/compare/snapshot', { case_name: snapName }); setSnapName(''); setSnapSel(null); await loadCmp(null) })} disabled={busy === 'snap'}
            className="text-[12px] px-3 py-1.5 rounded-lg bg-accent/15 border border-accent/40 text-blue-200 hover:bg-accent/25">Take snapshot of this case</button>
        </div>
        {!cmp ? <div className="tx-skeleton h-16" /> : !cmp.has_snapshot
          ? <div className="text-[12px] text-ink-faint">Take a snapshot, then load another case or run a live session: this panel shows what is new, gone or changed — matched by content, so reloads don't confuse it.</div>
          : (
            <div className="grid grid-cols-3 gap-3 text-[12px]">
              {[['Findings', cmp.findings, (x) => `${x.rule} ${x.level} · ${x.about || ''}`], ['Chains', cmp.chains, (x) => `${x.label} (${x.events})`], ['Events', cmp.events, (x) => x]].map(([name, d, fmt]) => (
                <div key={name} className="tx-inset p-3">
                  <div className="text-ink-text font-medium mb-1.5">{name} <span className="text-ink-faint font-normal">· {d.same} unchanged</span></div>
                  {d.new.slice(0, 6).map((x, i) => <div key={`n${i}`} className="text-emerald-300 truncate" title={fmt(x)}>+ {fmt(x)}</div>)}
                  {d.gone.slice(0, 6).map((x, i) => <div key={`g${i}`} className="text-sev-high/80 truncate" title={fmt(x)}>− {fmt(x)}</div>)}
                  {(d.new.length > 6 || d.gone.length > 6) && <div className="text-ink-faint">… {Math.max(0, d.new.length - 6) + Math.max(0, d.gone.length - 6)} more</div>}
                  {name === 'Findings' && d.level_changed?.map((x, i) => <div key={`l${i}`} className="text-amber-300">~ {x.rule}: {x.before} → {x.after}</div>)}
                  {!d.new.length && !d.gone.length && !(d.level_changed?.length) && <div className="text-ink-faint">no change</div>}
                </div>
              ))}
            </div>
          )}
      </Card>
    </div>
  )
}

/* ---------- Graph ---------- */
// Plain words for a bystander: the technical names stay available (tooltips, details panel)
const PLAIN_TYPE = {
  LOGIN: 'Logged in', LOGOFF: 'Logged off', FILE_ACCESSED: 'Opened file', FILE_MODIFIED: 'Changed file',
  FILE_COPIED: 'Copied file', FILE_DELETED: 'Deleted file', FILE_CREATED: 'Created file', PAGE_VISIT: 'Visited web page',
  FILE_DOWNLOAD: 'Downloaded file', DEVICE_CONNECTED: 'USB plugged in', DEVICE_DISCONNECTED: 'USB removed',
  LOG_CLEARED: 'Cleared event log', TIMESTAMP_ANOMALY: 'Timestamp mismatch', PROCESS_CREATED: 'Started program',
}
const TYPE_ICON = {
  LOGIN: 'user', LOGOFF: 'user', DEVICE_CONNECTED: 'plug', DEVICE_DISCONNECTED: 'plug', LOG_CLEARED: 'warn',
  PAGE_VISIT: 'search', PROCESS_CREATED: 'play', TIMESTAMP_ANOMALY: 'warn',
}
const PLAIN_SOURCE = { WINDOWS_EVENTLOG: 'Windows event log', FILESYSTEM_NTFS: 'File system (NTFS)', BROWSER: 'Browser history', USB: 'USB records' }
const PLAIN_ENTITY = { user: 'Person', file: 'File', device: 'USB device', process: 'Program' }
const PLAIN_RULE = {
  evidence_deletion: 'File copied, then deleted soon after', log_clearing: 'Event log cleared after activity',
  timestamp_anomaly: 'File timestamps look altered', mass_deletion: 'Many files deleted at once',
  metadata_modification: 'File disguised (name or size changed)',
}
const PLAIN_INDICATOR = {
  relevant_prior_activity: 'Relevant activity before it', short_temporal_distance: 'Happened soon after',
  multiple_related_events: 'Several related events', evidence_directly_affected: 'A file was affected',
}
const plainType = (t) => PLAIN_TYPE[t] || pretty(t)
const typeIcon = (t) => TYPE_ICON[t] || 'file'

/** Short, human name for an entity; the full value stays in the tooltip and details panel. */
function shortName(kind, label = '') {
  if (kind === 'device' && /USBSTOR/i.test(label)) {
    const ven = (label.match(/Ven_([^&\\]+)/i) || [])[1], prod = (label.match(/Prod_([^&\\]+)/i) || [])[1]
    const name = [ven, prod].filter(Boolean).join(' ')
    return name ? `${name} USB` : 'USB device'
  }
  if (kind === 'file' || kind === 'device') return label.split(/[\\/]/).filter(Boolean).pop() || label
  return label
}

function EventNode({ data: d, selected }) {
  const c = tcolor(d.type)
  const s = d.level ? SEV[d.level].c : null
  return (
    <div className="rounded-xl px-3 py-2.5 w-[156px] transition-all duration-300"
      title={`${d.type} · ${d.ts}`}
      style={{
        opacity: d.dim ? 0.22 : 1,
        background: 'linear-gradient(180deg,#151b29,#0e121b)',
        border: `1.5px solid ${selected ? '#5b9cff' : s || `${c}55`}`,
        boxShadow: selected ? '0 0 0 3px rgba(91,156,255,0.28), 0 0 22px rgba(91,156,255,0.35)' : s ? `0 0 16px ${s}44` : '0 6px 16px -8px rgba(0,0,0,.8)',
      }}>
      <Handle type="target" position={Position.Left} id="l" />
      <Handle type="source" position={Position.Right} id="r" />
      <Handle type="target" position={Position.Top} id="t" />
      <Handle type="source" position={Position.Bottom} id="b" />
      <Handle type="target" position={Position.Bottom} id="bt" />
      <div className="flex items-center gap-2">
        <span className="w-6 h-6 rounded-lg flex items-center justify-center shrink-0" style={{ background: `${c}1f`, color: c }}>
          <Icon name={typeIcon(d.type)} size={13} />
        </span>
        <span className="text-[12px] font-semibold text-ink-text leading-tight">{d.renamed ? 'Renamed file' : plainType(d.type)}</span>
      </div>
      <div className="flex items-center justify-between mt-1.5">
        <span className="text-[10.5px] text-ink-muted font-mono"><span className="text-ink-faint">#{d.step}</span> {hhmmss(d.ts)}</span>
        {d.level
          ? <span className="text-[9px] font-bold px-1.5 py-px rounded" style={{ color: s, background: `${s}22` }}>⚑ {d.level}</span>
          : <span className="text-[9px] text-ink-faint">not flagged</span>}
      </div>
    </div>
  )
}

function EntityNode({ data: d }) {
  const c = ENTITY[d.kind] || '#8e97ab'
  return (
    <div className="flex items-center gap-2.5 rounded-xl pl-2 pr-3.5 py-2 max-w-[240px] transition-opacity duration-300"
      title={d.label} style={{ opacity: d.dim ? 0.25 : 1, background: `${c}12`, border: `1px solid ${c}55` }}>
      <Handle type="source" position={Position.Bottom} />
      <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0" style={{ background: `${c}26`, color: c }}>
        <Icon name={d.kind === 'user' ? 'user' : d.kind === 'file' ? 'file' : d.kind === 'device' ? 'plug' : 'device'} size={14} />
      </span>
      <span className="min-w-0">
        <span className="block text-[9px] uppercase tracking-[0.14em]" style={{ color: c }}>{PLAIN_ENTITY[d.kind] || d.kind}</span>
        <span className="block text-[12px] font-semibold text-ink-text truncate">{shortName(d.kind, d.label)}</span>
      </span>
    </div>
  )
}

/** Row titles drawn on the canvas, so the layout explains itself. */
function LaneNode({ data: d }) {
  return (
    <div className="whitespace-nowrap select-none pointer-events-none inline-flex items-baseline gap-2 px-2.5 py-1 rounded-lg bg-[#0e121b] border border-white/[0.07]">
      <span className="text-[12px] font-semibold uppercase tracking-[0.1em] text-ink-muted">{d.title}</span>
      <span className="text-[11px] text-ink-faint">{d.hint}</span>
    </div>
  )
}

/** correlation arc hanging below the event row; depth grows with time distance */
function ArcEdge({ id, sourceX, sourceY, targetX, targetY, style, label, data }) {
  const h = Math.min(190, Math.max(36, Math.abs(targetX - sourceX) * 0.32))
  const path = `M${sourceX},${sourceY} C${sourceX},${sourceY + h} ${targetX},${targetY + h} ${targetX},${targetY}`
  return (
    <>
      <BaseEdge id={id} path={path} style={style} />
      {label && (
        <EdgeLabelRenderer>
          <div className="absolute text-[9.5px] font-mono px-1.5 rounded border border-[#2a4a80] bg-[#0e1626] text-blue-200 cursor-help transition-opacity duration-300"
            title={data?.why} style={{ pointerEvents: 'all', opacity: data?.dim ? 0.15 : 1,
              transform: `translate(-50%,-50%) translate(${(sourceX + targetX) / 2}px,${sourceY + h * 0.75}px)` }}>{label}</div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}
const nodeTypes = { ev: EventNode, ent: EntityNode, lane: LaneNode, spacer: () => <div style={{ width: 1, height: 1 }} /> }
const edgeTypes = { arc: ArcEdge }

function GraphLegend({ showEntities, setShowEntities }) {
  const item = 'flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-white/10 bg-[#0e121b]/85 text-ink-muted'
  return (
    <div className="absolute top-3 left-3 right-3 z-10 flex flex-wrap items-center gap-2 text-[11px]">
      <span className={item}><span className="w-3 h-3 rounded border-[1.5px] border-sev-high" style={{ boxShadow: '0 0 6px #ff6b6b88' }} />suspicious event</span>
      <span className={item}><span className="w-5 h-[2px] bg-[#3a4560]" />happened next</span>
      <span className={item} title="Scored from: how close in time, same person, same file, same device, same program">
        <svg width="22" height="10"><path d="M1 1 C1 9, 21 9, 21 1" fill="none" stroke="#5b9cff" strokeWidth="1.6" strokeDasharray="3 2" /></svg>
        linked · % = how strongly
      </span>
      <button onClick={() => setShowEntities((v) => !v)}
        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border transition-colors ${showEntities ? 'border-accent/40 bg-accent/10 text-blue-200' : 'border-white/10 bg-[#0e121b]/85 text-ink-muted'}`}>
        <span className={`w-3 h-3 rounded-sm border flex items-center justify-center ${showEntities ? 'border-accent bg-accent/30' : 'border-white/30'}`}>{showEntities ? '✓' : ''}</span>
        show who & what
      </button>
    </div>
  )
}

function GraphView({ data, flags }) {
  const [sel, setSel] = useState(null)
  const [showEntities, setShowEntities] = useState(true)
  const evAll = useMemo(() => Object.fromEntries(data.graph.nodes.filter((n) => n.kind === 'event').map((n) => [n.id, n])), [data])
  const base = useMemo(() => {
    const evs = data.graph.nodes.filter((n) => n.kind === 'event')
      .sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || '')).slice(0, 60)
    const ids = new Set(evs.map((n) => n.id))
    // one row per person, each in time order (wrapping at 10); correlation arcs hang below each row
    const PER = 10, DX = 174, DY = 300, Y0 = showEntities ? 150 : 0
    const step = Object.fromEntries(evs.map((n, i) => [n.id, i + 1]))  // global time order, shown as #n
    const groups = new Map()
    evs.forEach((n) => { const k = n.user || '(no user recorded)'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n) })
    const rows = []  // [{who, items, first}]
    groups.forEach((items, who) => {
      for (let i = 0; i < items.length; i += PER) rows.push({ who, items: items.slice(i, i + PER), first: i === 0 })
    })
    const nodes = [], edges = [], lanes = []
    rows.forEach((r, ri) => {
      const y = Y0 + ri * DY
      r.items.forEach((n, i) => nodes.push({
        id: n.id, type: 'ev',
        data: { type: n.event_type, ts: n.timestamp, level: flags[n.id], step: step[n.id], renamed: !!n.renamed_from },
        position: { x: i * DX, y },
      }))
      // "happened next" only between neighbours in the same row: no loops across the canvas
      r.items.slice(1).forEach((n, i) => edges.push({ id: `p${n.id}`, source: r.items[i].id, target: n.id,
        sourceHandle: 'r', targetHandle: 'l', type: 'smoothstep', style: { stroke: '#3a4560', strokeWidth: 1.4 } }))
      lanes.push({ id: `__lane_${ri}`, type: 'lane', selectable: false, draggable: false, position: { x: -4, y: y - 40 },
        data: r.first
          ? { title: groups.size > 1 ? `${r.who}'s activity →` : 'What happened →', hint: 'in time order · ⚑ = flagged by a rule' }
          : { title: `${r.who}, continued →`, hint: '' } })
    })
    const width = Math.min(PER, Math.max(...rows.map((r) => r.items.length), 1)) * DX
    data.graph.edges.forEach((e, i) => {
      if (!(ids.has(e.from) && ids.has(e.to))) return
      if (e.verb === 'correlated-with') {
        const pct = (e.score * 100).toFixed(0)
        edges.push({ id: `c${i}`, source: e.from, target: e.to, sourceHandle: 'b', targetHandle: 'bt', animated: true, type: 'arc',
          label: `${pct}%`, data: { why: `${pct}% linked: ${(e.factors || []).join('; ')}` },
          style: { stroke: '#5b9cff', strokeWidth: 1.5, strokeOpacity: 0.35 + 0.65 * e.score, filter: 'drop-shadow(0 0 3px rgba(91,156,255,.5))' } })
      }
    })
    if (showEntities) {
      const ents = data.graph.nodes.filter((n) => n.kind !== 'event')
      const linked = new Map()
      data.graph.edges.forEach((e, i) => {
        const ent = ents.find((n) => n.id === e.from && ids.has(e.to)) || ents.find((n) => n.id === e.to && ids.has(e.from))
        if (!ent) return
        const ev = ent.id === e.from ? e.to : e.from
        linked.set(ent.id, ent)
        if (edges.length < 260) edges.push({ id: `x${i}`, source: ent.id, target: ev, targetHandle: 't',
          style: { stroke: `${ENTITY[ent.kind] || '#8e97ab'}40`, strokeWidth: 1 } })
      })
      const list = [...linked.values()]
      const gap = list.length > 1 ? Math.max(250, width / list.length) : 0 // spread entities over the widest row
      const x0 = (width - gap * (list.length - 1)) / 2 - 100
      list.forEach((n, i) => nodes.push({
        id: n.id, type: 'ent', data: { kind: n.kind, label: n.label },
        position: { x: x0 + i * gap, y: 0 },
      }))
      nodes.push({ id: '__lane_who', type: 'lane', selectable: false, draggable: false,
        data: { title: 'Who & what was involved', hint: 'people, files and devices' }, position: { x: -4, y: -46 } })
    }
    if (evs.length) {
      const last = Y0 + (rows.length - 1) * DY
      nodes.push(...lanes)
      nodes.push({ id: '__lane_links', type: 'lane', selectable: false, draggable: false,
        data: { title: 'How strongly linked', hint: 'blue arcs above · hover a % to see why' }, position: { x: -4, y: last + 262 } })
      // invisible nodes above and below so fitView leaves room for the legend and the arcs
      nodes.push({ id: '__spacer', type: 'spacer', selectable: false, data: {}, position: { x: 0, y: last + 300 } })
      nodes.push({ id: '__spacer_top', type: 'spacer', selectable: false, data: {}, position: { x: 0, y: showEntities ? -110 : -90 } })
    }
    return { nodes, edges, count: evs.length }
  }, [data, flags, showEntities])

  // focus mode: a selected node keeps its own links lit; everything else fades back
  const rf = useMemo(() => {
    if (!sel) return base
    const near = new Set([sel])
    base.edges.forEach((e) => { if (e.source === sel) near.add(e.target); if (e.target === sel) near.add(e.source) })
    return {
      ...base,
      nodes: base.nodes.map((n) => (n.type === 'ev' || n.type === 'ent') ? { ...n, data: { ...n.data, dim: !near.has(n.id) } } : n),
      edges: base.edges.map((e) => {
        const on = e.source === sel || e.target === sel
        return { ...e, animated: e.animated && on, data: { ...e.data, dim: !on },
          style: { ...e.style, opacity: on ? 1 : 0.1, strokeWidth: on ? (e.style.strokeWidth || 1) + 0.6 : e.style.strokeWidth } }
      }),
    }
  }, [base, sel])

  const detail = sel ? data.graph.nodes.find((n) => n.id === sel) : null
  const goTo = (id) => setSel(id)
  return (
    <div className="tx-panel overflow-hidden h-[680px] flex animate-fade-up">
      <div className="flex-1 min-w-0 relative">
        <GraphLegend showEntities={showEntities} setShowEntities={setShowEntities} />
        <div className="absolute bottom-3 left-1/2 -translate-x-1/2 z-10 text-[11.5px] px-3 py-1.5 rounded-full border border-white/10 bg-[#0e121b]/90 text-ink-muted flex items-center gap-2">
          <Icon name="search" size={13} className="text-accent" />
          {detail ? 'Click empty space to show everything again' : 'Click any event to see where it came from and why it was flagged'}
        </div>
        <ReactFlow nodes={rf.nodes} edges={rf.edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
          onNodeClick={(_, n) => (n.type === 'ev' || n.type === 'ent') && setSel(n.id)}
          onPaneClick={() => setSel(null)} fitView fitViewOptions={{ padding: 0.1 }} minZoom={0.2} proOptions={{ hideAttribution: true }}>
          <Background color="#1d2333" gap={22} size={1.2} />
          <Controls showInteractive={false} />
          {base.count > 20 && (
            <MiniMap pannable zoomable maskColor="rgba(7,9,16,0.75)"
              nodeColor={(n) => (n.type === 'ent' ? ENTITY[n.data.kind] : n.type === 'ev' ? (n.data.level ? SEV[n.data.level].c : tcolor(n.data.type)) : 'transparent')} />
          )}
        </ReactFlow>
      </div>
      {detail && <GraphDetails detail={detail} data={data} evAll={evAll} goTo={goTo} close={() => setSel(null)} />}
    </div>
  )
}

function DetailSection({ title, tier, children }) {
  return (
    <section>
      <div className="flex items-center gap-2 mb-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-muted">{title}</h3>
        {tier && <TierBadge tier={tier} />}
      </div>
      {children}
    </section>
  )
}

function EventLink({ n, onClick, extra }) {
  return (
    <button onClick={onClick} className="w-full text-left flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-white/[0.03] border border-white/[0.06] hover:border-accent/40 hover:bg-accent/[0.06] transition-colors">
      <span style={{ color: tcolor(n.event_type) }}><Icon name={typeIcon(n.event_type)} size={12} /></span>
      <span className="text-[11.5px] text-ink-text">{plainType(n.event_type)}</span>
      <span className={`text-[10.5px] text-ink-faint ${M}`}>{hhmmss(n.timestamp)}</span>
      {extra && <span className="ml-auto text-[10.5px] text-blue-200">{extra}</span>}
    </button>
  )
}

function GraphDetails({ detail, data, evAll, goTo, close }) {
  const linkScore = (a, b) => {
    const e = data.graph.edges.find((x) => x.verb === 'correlated-with' && ((x.from === a && x.to === b) || (x.from === b && x.to === a)))
    return e ? `${(e.score * 100).toFixed(0)}% linked` : null
  }
  return (
    <aside className="w-[390px] shrink-0 border-l border-white/[0.06] bg-[#0b0f18]/85 flex flex-col animate-fade-up">
      <header className="flex items-start justify-between gap-3 px-5 pt-4 pb-3 border-b border-white/[0.05]">
        {detail.kind === 'event' ? (
          <div className="flex items-center gap-3 min-w-0">
            <span className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0" style={{ background: `${tcolor(detail.event_type)}22`, color: tcolor(detail.event_type) }}>
              <Icon name={typeIcon(detail.event_type)} size={17} />
            </span>
            <div className="min-w-0">
              <div className="text-[15px] font-semibold text-ink-text">{detail.renamed_from ? 'Renamed file' : plainType(detail.event_type)}</div>
              <div className={`text-[11px] text-ink-muted ${M}`}>{(detail.timestamp || '').replace('T', ' ').slice(0, 19)} UTC</div>
            </div>
          </div>
        ) : (
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-[0.14em]" style={{ color: ENTITY[detail.kind] }}>{PLAIN_ENTITY[detail.kind] || detail.kind}</div>
            <div className="text-[15px] font-semibold text-ink-text truncate">{shortName(detail.kind, detail.label)}</div>
          </div>
        )}
        <button onClick={close} className="text-ink-faint hover:text-ink-text text-xl leading-none px-1" aria-label="Close">×</button>
      </header>

      <div className="p-5 overflow-auto flex-1 space-y-5 text-[12px]">
        {detail.kind === 'event' ? (
          <>
            <DetailSection title="What happened" tier="Evidence">
              <dl className="tx-inset p-3 grid grid-cols-[86px_1fr] gap-y-1.5 gap-x-2">
                <dt className="text-ink-faint">Who</dt><dd className="text-ink-text">{detail.user || '—'}</dd>
                {detail.renamed_from && <><dt className="text-ink-faint">Renamed from</dt><dd className={`text-ink-text break-all ${M} text-[11px]`}>{detail.renamed_from}</dd></>}
                <dt className="text-ink-faint">{detail.renamed_from ? 'New name' : 'To what'}</dt><dd className={`text-ink-text break-all ${M} text-[11px]`}>{detail.object || '—'}</dd>
                <dt className="text-ink-faint">Recorded in</dt><dd className="text-ink-text">{PLAIN_SOURCE[detail.source] || detail.source}</dd>
              </dl>
            </DetailSection>

            <DetailSection title="Where this came from">
              <dl className="tx-inset p-3 grid grid-cols-[86px_1fr] gap-y-1.5 gap-x-2 text-[11px]">
                <dt className="text-ink-faint">Read by</dt><dd className={`text-ink-text ${M}`}>{detail.provenance.parser_name} {detail.provenance.parser_version}</dd>
                <dt className="text-ink-faint">From file</dt><dd className={`text-ink-text break-all ${M}`}>{detail.provenance.source_file}</dd>
                <dt className="text-ink-faint">Fingerprint</dt><dd className={`text-ink-text break-all ${M}`} title={detail.hash}>SHA-256 {detail.hash.slice(0, 20)}…</dd>
                <dt className="text-ink-faint">Event ID</dt><dd className={`text-ink-muted ${M}`}>{short(detail.id)}</dd>
              </dl>
              <p className="text-[10.5px] text-ink-faint mt-1.5">The fingerprint proves this record hasn't changed since it was read.</p>
            </DetailSection>

            <DetailSection title="Why it was flagged" tier={detail.flagged_by.length ? 'Correlation' : null}>
              {detail.flagged_by.length === 0
                ? <p className="text-ink-muted">Not flagged by any rule. It appears here because it is linked to other events.</p>
                : detail.flagged_by.map((f, i) => {
                  const c = SEV[f.level].c
                  return (
                    <div key={i} className="tx-inset p-3 mb-2 last:mb-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-ink-text font-medium">{PLAIN_RULE[f.rule] || f.rule}</span>
                        <LevelChip level={f.level} />
                        <span className={`ml-auto ${M}`} style={{ color: c }}>{f.score.toFixed(2)}</span>
                      </div>
                      <div className={`text-[10px] text-ink-faint mt-0.5 ${M}`}>rule: {f.rule}</div>
                      <div className="mt-2.5 space-y-1.5">
                        {Object.entries(f.indicators).map(([k, v]) => (
                          <div key={k} className="flex items-center gap-2.5" title={k}>
                            <span className="text-[11px] text-ink-muted w-[160px] shrink-0">{PLAIN_INDICATOR[k] || k}</span>
                            <Meter value={v} color={c} className="h-1" />
                            <span className={`text-[10.5px] w-8 text-right text-ink-text ${M}`}>{v.toFixed(2)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )
                })}
            </DetailSection>

            {detail.related_evidence.length > 0 && (
              <DetailSection title="Connected events">
                <div className="space-y-1.5">
                  {detail.related_evidence.filter((id) => evAll[id]).map((id) => (
                    <EventLink key={id} n={evAll[id]} onClick={() => goTo(id)} extra={linkScore(detail.id, id)} />
                  ))}
                </div>
              </DetailSection>
            )}

            {detail.chains.map((c, i) => (
              <DetailSection key={i} title="What it might mean" tier="Hypothesis">
                <div className="rounded-xl p-3 border border-amber-400/25 bg-amber-400/[0.04]">
                  <div className="text-ink-text font-medium">{c.label}</div>
                  <p className="text-ink-text mt-1 leading-relaxed">{c.hypothesis.charAt(0).toUpperCase() + c.hypothesis.slice(1)}.</p>
                  <div className="mt-3 pt-2.5 border-t border-amber-400/20">
                    <div className="flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[0.12em] text-amber-300"><Icon name="warn" size={12} />What this does NOT prove</div>
                    <p className="text-[11.5px] text-amber-100/75 italic mt-1 leading-relaxed">{c.limitation}</p>
                  </div>
                </div>
              </DetailSection>
            ))}
          </>
        ) : (
          <DetailSection title={`Involved in ${data.graph.edges.filter((e) => e.from === detail.id || e.to === detail.id).length} events`}>
            <p className={`text-[11px] text-ink-faint break-all mb-2 ${M}`}>{detail.label}</p>
            <div className="space-y-1.5">
              {data.graph.edges.filter((e) => (e.from === detail.id && evAll[e.to]) || (e.to === detail.id && evAll[e.from]))
                .map((e) => evAll[e.from === detail.id ? e.to : e.from])
                .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
                .map((n) => <EventLink key={n.id} n={n} onClick={() => goTo(n.id)} />)}
            </div>
          </DetailSection>
        )}
      </div>
    </aside>
  )
}

/* ---------- Report ---------- */
// wide report tables scroll sideways instead of overflowing the card
const REPORT_COMPONENTS = { table: ({ node, ...p }) => <div className="overflow-x-auto"><table {...p} /></div> }

function ReportView() {
  const [md, setMd] = useState(null)
  useEffect(() => { api.report().then(setMd).catch((e) => setMd(`Error: ${e}`)) }, [])
  return (
    <Card className="max-w-[1100px] mx-auto" title="Case report" badge={<TierBadge tier="Evidence" />}
      right={<button onClick={() => window.print()}
        className="tx-no-print flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-accent/40 bg-accent/10 text-blue-200 hover:bg-accent/20 transition-colors">
        <Icon name="print" size={13} />Print / PDF</button>}
      bodyClass="px-10 py-8">
      {md == null
        ? <div className="space-y-3">{[70, 95, 88, 60, 92].map((w, i) => <div key={i} className="tx-skeleton h-3.5" style={{ width: `${w}%` }} />)}</div>
        : <div className="tx-report"><ReactMarkdown remarkPlugins={[remarkGfm]} components={REPORT_COMPONENTS}>{md}</ReactMarkdown></div>}
    </Card>
  )
}

/* ---------- loading / error ---------- */
function Loading() {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-5 h-[220px] tx-skeleton" />
        <div className="col-span-7 grid grid-cols-3 gap-4">{Array.from({ length: 6 }, (_, i) => <div key={i} className="h-[102px] tx-skeleton" />)}</div>
      </div>
      <div className="h-[180px] tx-skeleton" />
    </div>
  )
}

function ApiError({ err }) {
  return (
    <div className="tx-panel p-8 max-w-xl mx-auto mt-10 text-center animate-fade-up">
      <div className="w-12 h-12 rounded-2xl mx-auto mb-4 flex items-center justify-center bg-sev-high/10 border border-sev-high/30 text-sev-high"><Icon name="warn" size={22} /></div>
      <div className="text-[16px] font-semibold">Can’t reach the TRACE-X engine</div>
      <p className={`text-[11.5px] text-ink-faint mt-1.5 ${M}`}>{err}</p>
      <p className="text-[12.5px] text-ink-muted mt-4">Start the backend from the repo root:</p>
      <code className={`block mt-2 text-[12px] tx-inset px-3 py-2 text-blue-200 ${M}`}>uvicorn backend.app.main:app</code>
    </div>
  )
}

/* ---------- app ---------- */
/* ---------- re-run analysis feedback (deliberately over the top) ---------- */
const FX_STEPS = ['Reading the evidence store', 'Anti-forensic rules', 'Correlation + chains', 'Forensic graph', 'Timeline gaps']
const caseStats = (d) => ({ events: d.events.length, findings: d.suspicious.length, chains: d.chains.length, nodes: d.graph.nodes.length })

function ReanalyseFX({ fx }) {
  const [step, setStep] = useState(0)
  useEffect(() => {
    if (!fx) return
    setStep(0)
    const id = setInterval(() => setStep((s) => Math.min(s + 1, FX_STEPS.length)), 240)
    return () => clearInterval(id)
  }, [fx?.id])
  const parts = useMemo(() => Array.from({ length: 34 }, (_, i) => {
    const a = (i / 34) * Math.PI * 2 + Math.random() * 0.4
    const r = 120 + Math.random() * 320
    return { dx: `${Math.cos(a) * r}px`, dy: `${Math.sin(a) * r}px`, c: ['#38d6f5', '#8b7bff', '#5b9cff', '#ff6b6b', '#fbbf24'][i % 5],
      delay: Math.random() * 120, size: 3 + Math.random() * 5, dur: 650 + Math.random() * 500 }
  }), [fx?.id])
  if (!fx) return null
  const { x, y } = fx.origin
  const scanning = fx.phase === 'scan'
  const done = fx.phase === 'done' || (fx.phase === 'out' && fx.now)
  const fail = fx.phase === 'fail' || (fx.phase === 'out' && !fx.now)
  const changed = done && fx.prev && Object.keys(fx.now).filter((k) => fx.now[k] !== fx.prev[k])
  const ticked = done ? FX_STEPS.length : step
  return (
    <div key={fx.id} className="fixed inset-0 z-[100] pointer-events-none overflow-hidden" aria-live="polite">
      {/* flash + grid + laser + shockwave + particles: the burst on click */}
      <div className="fx-motion absolute inset-0" style={{ background: `radial-gradient(circle at ${x}px ${y}px, rgba(56,214,245,.38), rgba(139,123,255,.16) 28%, transparent 62%)`, animation: 'fx-flash 1.2s ease-out both' }} />
      <div className="fx-motion absolute inset-0" style={{ backgroundImage: 'linear-gradient(rgba(56,214,245,.13) 1px, transparent 1px), linear-gradient(90deg, rgba(56,214,245,.13) 1px, transparent 1px)', backgroundSize: '48px 48px', animation: 'fx-grid 1.5s ease-out both' }} />
      <div className="fx-motion absolute inset-x-0 top-0 h-[140px]" style={{ animation: 'fx-scan 1.1s cubic-bezier(.65,0,.35,1) 2 both' }}>
        <div className="absolute inset-0" style={{ background: 'linear-gradient(to bottom, transparent, rgba(56,214,245,.12) 85%, rgba(139,123,255,.22))' }} />
        <div className="absolute inset-x-0 bottom-0 h-[2px]" style={{ background: 'linear-gradient(90deg, transparent, #38d6f5 15%, #fff 50%, #8b7bff 85%, transparent)', boxShadow: '0 0 16px 4px rgba(56,214,245,.85), 0 0 70px 14px rgba(139,123,255,.45)' }} />
      </div>
      {[0, 140, 280].map((d, i) => (
        <div key={d} className="fx-motion absolute w-10 h-10 rounded-full" style={{ left: x, top: y, '--s': 34 + i * 10,
          border: `2px solid ${['#38d6f5', '#8b7bff', '#5b9cff'][i]}`, boxShadow: `0 0 24px ${['#38d6f5', '#8b7bff', '#5b9cff'][i]}`,
          animation: `fx-ring 1.3s cubic-bezier(.15,.7,.3,1) ${d}ms both` }} />
      ))}
      {parts.map((p, i) => (
        <span key={i} className="fx-motion absolute rounded-full" style={{ left: x, top: y, width: p.size, height: p.size, background: p.c,
          boxShadow: `0 0 10px ${p.c}`, '--dx': p.dx, '--dy': p.dy, animation: `fx-particle ${p.dur}ms cubic-bezier(.1,.8,.3,1) ${p.delay}ms both` }} />
      ))}

      {/* the HUD: engines ticking off, then the verdict */}
      <div className="absolute left-1/2 top-[88px] w-[440px] rounded-2xl border backdrop-blur-xl"
        style={{ transform: 'translateX(-50%)', background: 'linear-gradient(160deg, rgba(14,18,27,.94), rgba(10,13,21,.9))',
          borderColor: fail ? 'rgba(255,107,107,.55)' : done ? 'rgba(52,211,153,.55)' : 'rgba(56,214,245,.5)',
          boxShadow: `0 0 0 1px rgba(255,255,255,.03), 0 30px 80px -20px rgba(0,0,0,.9), 0 0 60px -10px ${fail ? 'rgba(255,107,107,.55)' : done ? 'rgba(52,211,153,.5)' : 'rgba(56,214,245,.55)'}`,
          animation: fx.phase === 'out' ? 'fx-hud-out .45s ease-in both' : 'fx-hud-in .45s cubic-bezier(.2,.9,.2,1.15) both' }}>
        <div className="px-5 pt-4 pb-3 flex items-center gap-3.5 border-b border-white/[0.06]">
          <div className="relative w-11 h-11 shrink-0">
            {scanning && <>
              <div className="absolute inset-0 rounded-full animate-spin" style={{ background: 'conic-gradient(from 0deg, transparent, #38d6f5, #8b7bff, transparent 70%)', animationDuration: '.7s' }} />
              <div className="absolute inset-[3px] rounded-full bg-[#0b0f18] flex items-center justify-center"><Icon name="refresh" size={18} className="text-accent-cyan animate-spin" /></div>
            </>}
            {done && <>
              <div className="absolute inset-0 rounded-full border-2 border-emerald-400" style={{ animation: 'fx-check-ring .9s ease-out both' }} />
              <div className="absolute inset-0 rounded-full bg-emerald-400/15 border border-emerald-400/60 flex items-center justify-center" style={{ animation: 'fx-stamp .5s cubic-bezier(.2,.9,.2,1.2) both' }}>
                <Icon name="check" size={24} className="text-emerald-300" stroke={2.2} />
              </div>
            </>}
            {fail && <div className="absolute inset-0 rounded-full bg-sev-high/15 border border-sev-high/60 flex items-center justify-center"><Icon name="warn" size={22} className="text-sev-high" /></div>}
          </div>
          <div className="min-w-0">
            <div className={`text-[15px] font-bold tracking-[0.18em] ${scanning ? 'fx-glitch text-accent-cyan' : done ? 'text-emerald-300' : 'text-sev-high'} ${M}`}
              style={done ? { animation: 'fx-stamp .55s cubic-bezier(.2,.9,.2,1.2) both', textShadow: '0 0 20px rgba(52,211,153,.6)' } : undefined}>
              {scanning ? 'RE-ANALYSING CASE' : done ? 'ANALYSIS RE-RUN ✓' : 'API UNREACHABLE'}
            </div>
            <div className="text-[11px] text-ink-muted mt-0.5">
              {scanning ? 'Every engine is re-running on the stored evidence…'
                : done ? <>Completed in <span className={`text-emerald-300 ${M}`}>{fx.ms} ms</span> · {new Date().toLocaleTimeString([], { hour12: false })}</>
                  : 'Start the API window, then try again.'}
            </div>
          </div>
        </div>
        <div className="px-5 py-3 space-y-1.5">
          {FX_STEPS.map((s, i) => {
            const ok = i < ticked
            return (
              <div key={s} className={`flex items-center gap-2.5 text-[12px] transition-all duration-300 ${ok ? 'text-ink-text' : 'text-ink-faint'}`}>
                <span className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 transition-all duration-300 ${ok ? 'bg-emerald-400/20 shadow-[0_0_10px_rgba(52,211,153,.7)]' : 'border border-white/15'}`}>
                  {ok ? <span className="w-1.5 h-1.5 rounded-full bg-emerald-300" />
                    : scanning && i === ticked ? <span className="w-2.5 h-2.5 rounded-full border-2 border-accent-cyan border-t-transparent animate-spin" /> : null}
                </span>
                <span className="flex-1">{s}</span>
                <span className={`text-[10px] ${M} ${ok ? 'text-emerald-300/80' : 'text-ink-faint'}`}>{ok ? 'OK' : scanning && i === ticked ? 'RUN' : '···'}</span>
              </div>
            )
          })}
          <div className="h-1.5 mt-2.5 rounded-full bg-white/[0.05] overflow-hidden">
            <div className={`h-full rounded-full transition-all duration-300 ${fail ? 'bg-sev-high' : 'fx-stripes'}`}
              style={{ width: `${fail ? 100 : (ticked / FX_STEPS.length) * 100}%`, backgroundColor: fail ? undefined : done ? '#34d399' : '#38d6f5', boxShadow: `0 0 12px ${done ? '#34d399' : '#38d6f5'}` }} />
          </div>
        </div>
        {done && (
          <div className="px-5 pb-4">
            <div className="grid grid-cols-4 gap-2">
              {[['events', fx.now.events], ['findings', fx.now.findings], ['chains', fx.now.chains], ['nodes', fx.now.nodes]].map(([k, v], i) => (
                <div key={k} className={`rounded-lg px-2 py-1.5 text-center border ${changed?.includes(k) ? 'border-amber-400/50 bg-amber-400/10' : 'border-white/[0.06] bg-white/[0.02]'}`}
                  style={{ animation: `fx-stamp .45s cubic-bezier(.2,.9,.2,1.2) ${120 + i * 80}ms both` }}>
                  <div className={`text-[17px] font-bold leading-tight ${changed?.includes(k) ? 'text-amber-300' : 'text-ink-text'} ${M}`}>{v}</div>
                  <div className="text-[9.5px] uppercase tracking-wider text-ink-faint">{k}</div>
                </div>
              ))}
            </div>
            <div className="mt-2.5 text-[11px] text-center">
              {!fx.prev ? <span className="text-ink-muted">Fresh analysis loaded.</span>
                : changed.length ? <span className="text-amber-300">{changed.length} figure{changed.length > 1 ? 's' : ''} changed since the last run: new evidence in the store.</span>
                  : <span className="text-ink-muted">Identical to the last run: the evidence store hasn't changed, so neither have the conclusions.</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function App() {
  const [tab, setTab] = useState('Overview')
  const [scenario, setScenario] = useState('combined')
  const [caseName, setCaseName] = useState('active store')
  const [reloadKey, setReloadKey] = useState(0)
  const [busy, setBusy] = useState(false)
  const [live, setLive] = useState(false)
  const [liveRunning, setLiveRunning] = useState(false)
  const [updated, setUpdated] = useState(null)
  const { data, err } = useCase(scenario, reloadKey)
  // an API already serving a live store (a running live session, or TRACEX_DB=.../live.db) resumes Live mode
  useEffect(() => {
    api.health().then((h) => {
      if (h.mode === 'live') {
        setLive(true); setLiveRunning(!!h.live_running)
        setCaseName(h.live_running ? 'live session (resumed)' : `live store · ${h.store}`)
      }
    }).catch(() => {})
  }, [])
  const startLive = async (mode, watch) => {
    setBusy(true)
    try {
      await api.liveStart(mode === 'scripted' ? { mode } : { mode, watch })
      setCaseName(mode === 'scripted' ? 'live_copy_to_usb · dynamic ground truth' : `live monitor · ${watch[0]}`)
      setLive(true); setLiveRunning(true)
      setReloadKey((k) => k + 1); setTab('Overview')
    } finally { setBusy(false) }
  }
  const stopLive = async () => {
    await api.liveStop()
    setLiveRunning(false); setLive(false) // the session's events stay on screen until a scenario is loaded
    setCaseName((c) => `${c} · stopped`)
  }
  useEffect(() => {
    if (!live) return
    const id = setInterval(() => setReloadKey((k) => k + 1), 3000)
    return () => clearInterval(id)
  }, [live])
  useEffect(() => { if (data) setUpdated(new Date()) }, [data])
  // manual re-run: burst from the button, then report what came back (and whether anything changed)
  const [fx, setFx] = useState(null)
  const rerun = (e) => {
    const r = e?.currentTarget?.getBoundingClientRect()
    setFx({ id: Date.now(), phase: 'scan', t0: performance.now(), from: data, fromErr: err, prev: data ? caseStats(data) : null,
      origin: r ? { x: r.left + r.width / 2, y: r.top + r.height / 2 } : { x: window.innerWidth / 2, y: 60 } })
    setReloadKey((k) => k + 1)
  }
  useEffect(() => {
    if (!fx || fx.phase !== 'scan') return
    const fresh = data && data !== fx.from
    if (!fresh && !(err && err !== fx.fromErr)) return
    const ms = Math.round(performance.now() - fx.t0)
    const t = setTimeout(() => setFx((f) => (f?.id === fx.id ? { ...f, phase: fresh ? 'done' : 'fail', ms, now: fresh ? caseStats(data) : null } : f)),
      Math.max(0, fx.t0 + 1400 - performance.now())) // let the engine list tick through before the verdict
    return () => clearTimeout(t)
  }, [data, err, fx])
  useEffect(() => {
    if (!fx) return
    const timers = fx.phase === 'scan' ? [setTimeout(() => setFx((f) => (f?.id === fx.id && f.phase === 'scan' ? { ...f, phase: 'fail' } : f)), 10000)]
      : fx.phase === 'out' ? [setTimeout(() => setFx((f) => (f?.id === fx.id ? null : f)), 450)]
        : [setTimeout(() => setFx((f) => (f?.id === fx.id ? { ...f, phase: 'out' } : f)), fx.phase === 'done' ? 2600 : 3200)]
    return () => timers.forEach(clearTimeout)
  }, [fx?.id, fx?.phase])
  const load = async (s) => {
    setBusy(true)
    try {
      await api.loadScenario(s) // also ends any live session and switches back to the case store
      setLive(false); setLiveRunning(false)
      setScenario(`${s}@${Date.now()}`)
      setCaseName(s) // load-scenario replaces the stored case
      setReloadKey((k) => k + 1)
      setTab('Overview')
    } finally { setBusy(false) }
  }
  return (
    <div className="flex min-h-screen min-w-[1024px] text-ink-text">
      <Sidebar tab={tab} setTab={setTab} data={data} />
      <main className="flex-1 min-w-0 px-8 py-6">
        <div className="max-w-[1400px] mx-auto">
          <TopBar tab={tab} caseName={caseName} err={err} data={data} onLoad={load} busy={busy}
            onRefresh={rerun} rerunning={fx?.phase === 'scan'} live={live} setLive={setLive} updated={updated}
            liveRunning={liveRunning} onLiveStart={startLive} onLiveStop={stopLive} />
          {err && <ApiError err={err} />}
          {!data && !err && tab !== 'Report' && <Loading />}
          <div className={fx?.phase === 'done' ? 'fx-rescan' : ''}>
            <Tabbed data={data} err={err} tab={tab} onLoad={load} goto={setTab} />
          </div>
        </div>
      </main>
      <ReanalyseFX fx={fx} />
    </div>
  )
}

function Tabbed({ data, err, tab, onLoad, goto }) {
  if (tab === 'Report') return <ReportView />
  if (!data || err) return null
  return <TabContent data={data} tab={tab} onLoad={onLoad} goto={goto} />
}

function TabContent({ data, tab, onLoad, goto }) {
  const flags = useFlags(data)
  return (
    <div key={tab}>
      {tab === 'Overview' && <Overview data={data} flags={flags} onLoad={onLoad} goto={goto} />}
      {tab === 'Timeline' && <Timeline data={data} flags={flags} />}
      {tab === 'Findings' && <Findings data={data} flags={flags} />}
      {tab === 'Graph' && <GraphView data={data} flags={flags} />}
      {tab === 'Assurance' && <Assurance data={data} />}
    </div>
  )
}
