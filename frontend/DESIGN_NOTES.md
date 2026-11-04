# TRACE-X Frontend — DESIGN_NOTES

"Forensic instrument" redesign (v2). Same API bindings, data shapes and endpoints;
React Flow, Tailwind, react-markdown kept; no new dependencies, no webfonts
(offline-safe). Supersedes the v1 flat SIEM theme.

## Look

- **Ambient backdrop** — fixed `body::before` layer: two soft blue/violet glows +
  a faint 32px measurement grid over `#070910`.
- **Glass panels** — `.tx-panel` (translucent gradient fill, hairline white/7%
  border, top-edge highlight, backdrop blur, 14px radius); `.tx-inset` for nested
  rows. Shared classes live in `src/index.css` `@layer components`.
- **Accent** — blue→violet gradient (`#5b9cff` → `#8b7bff`) for active nav, the
  primary action and the brand mark; `.tx-gradient-text` for the "-X".
- **Glow = signal** — only severity and correlation glow (flagged dots/nodes,
  severity bars, correlation arcs). Neutral data stays flat.
- **Icons** — inline stroke SVG set in `App.jsx` (`ICONS`), replacing emoji.

## Color tokens

| Token | Hex | Use |
|---|---|---|
| `ink.bg` | `#070910` | app background |
| `ink.panel` / `panel2` | `#0e121b` / `#141926` | solid fallbacks, popovers |
| `ink.border` | `#1e2533` | borders, table rules |
| `ink.text` / `muted` / `faint` | `#e8ecf4` / `#8e97ab` / `#5a6377` | text tiers |
| `accent` / `accent.2` | `#5b9cff` / `#8b7bff` | accent gradient |
| `sev.high` / `med` / `low` | `#ff6b6b` / `#fbbf24` / `#60a5db` | severity |

Event-type hues unchanged from v1 (`ETYPE` in `App.jsx`); entity hues: user blue,
file teal, device orange.

## Layout

1. **Sidebar shell** — fixed left nav with live counts (events / findings / graph
   nodes) and the Evidence · Correlation · Hypothesis legend always visible.
   Top bar: case breadcrumb, engine status pill, refresh, scenario menu.
2. **Overview** — case-posture gauge (peak suspicion score, explicitly "not a
   verdict"), six count-up stat tiles, activity histogram (flagged bins red),
   severity stacked bar, top findings, chain spotlight.
3. **Chains as steppers** — each chain is a numbered event flow; hypothesis and
   its "does not establish" limitation are side-by-side cards, so the epistemic
   split is visual, not just textual.
4. **Timeline** — SVG lanes with UTC time axis, hatched gap bands, glowing
   severity rings, hover/pinned tooltip, synced sortable event log beneath.
5. **Findings** — one card per finding: score ring, description, indicator
   meters (0–1 values as bars), evidence-ID chips.
6. **Graph as arc diagram** — events in one chronological row (wraps at 10),
   entities above, `preceded` as thin rails, `correlated-with` as animated arcs
   below the row whose depth grows with time distance and opacity with score.
   Provenance opens as a right-hand drawer so the graph keeps full width.
7. **Report** — document-width (900px) rendered Markdown with styled tables,
   code chips and section rules; Print/PDF strips the chrome.
8. **Motion** — fade-up on cards, count-up numbers, animated arcs; all disabled
   under `prefers-reduced-motion`. 1024px min width kept.

## Dev note

`vite.config.js` reads `TRACEX_API` (default `http://127.0.0.1:8000`) for the
proxy target, for machines where :8000 is taken.
