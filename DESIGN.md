# DESIGN.md

Design system and style guide for the **EDR Logs Graph Analyzer** frontend.

This document standardizes the visual language so new UI stays consistent and
colors do not drift across files. It is the reference for anyone touching
`frontend/src`. It is **not** a branding or product doc.

- **Stack:** React 19 + Vite + Tailwind CSS v4 + Cytoscape.js.
- **Theme:** dark-first, toggled by a `dark` class on `<html>`.
- **Source of truth for graph colors:** `frontend/src/components/cytoscapeStyles.js`
  (`NODE_GROUPS`).

---

## 1. Principles

1. **Single source of truth.** A color is defined in exactly one place. Graph
   node colors live only in `NODE_GROUPS`; do not re-declare them elsewhere.
2. **Tokens by role, not by value.** Prefer semantic names (accent, danger,
   muted) over "the blue one", so a palette change is a one-file edit.
3. **Dark mode is a first-class mode.** Every styled element ships both a light
   and a `dark:` variant. There is no separate dark stylesheet.
4. **Utility-first.** Styling is expressed with Tailwind classes in JSX. Avoid
   ad-hoc CSS; the only global CSS is `index.css` (base body + scrollbar).
5. **Calm default, loud signal.** Neutral slate carries the layout; saturated
   colors are reserved for state (selection, errors, node types, alerts).

---

## 2. Color system

### 2.1 Neutrals (layout)

Tailwind's `slate` scale is the neutral palette. Light mode uses the low end,
dark mode the high end.

| Role | Light | Dark |
| --- | --- | --- |
| App / page background | `bg-white` / `bg-slate-50` | `bg-slate-900` |
| Sidebar & panels | `bg-white` | `bg-slate-800` |
| Canvas background | `bg-slate-100` | `bg-[#222]` |
| Borders / dividers | `border-slate-200` | `border-slate-700` |
| Input borders | `border-slate-300` | `border-slate-600` |
| Muted text | `text-slate-500` | `text-slate-400` |
| Secondary text | `text-slate-600` | `text-slate-300` |
| Primary text | `text-slate-900` | `text-slate-50` / `text-white` |
| Subtle surface (inputs, pre) | `bg-slate-50` | `bg-slate-900` |

### 2.2 Semantic colors

| Role | Token / classes | Usage |
| --- | --- | --- |
| Accent (interactive) | `blue-500` / `blue-600` | Primary buttons, active tab, focus ring, active dataset, selection borders |
| Accent surface | `bg-blue-50` / `dark:bg-blue-900/20` – `dark:bg-blue-900/30` | Active tab / dataset background |
| Success | `green-500`, `dark:text-green-400` | Copy-confirmed icon, raw JSON text in dark mode |
| Danger | `red-500` / `red-600`, `text-red-600 dark:text-red-400` | Errors, delete, "Hide" action |
| Danger surface | `bg-red-100 dark:bg-red-900/30` | Danger button background |
| Warning | `orange-*`, `amber-400/600` | Hidden-elements banner, truncation notice |

> Focus rings: `focus:ring-1 focus:ring-blue-500`.

### 2.3 Graph node groups (authoritative)

Defined **only** in `NODE_GROUPS` (`frontend/src/components/cytoscapeStyles.js`)
and consumed by both the Cytoscape stylesheet and the in-graph legend. The base
node style sets `border-width: 2`; the table lists overrides.

| `group` | Legend label | Shape | Background | Border | Border width |
| --- | --- | --- | --- | --- | --- |
| `process` | Process | `round-rectangle` | `#4d0000` | `#ff4d4d` | 2 |
| `file` | File | `rectangle` | `#00264d` | `#4da6ff` | 2 |
| `module` | Module | `hexagon` | `#4d0099` | `#b366ff` | 2 |
| `registry` | Registry | `rectangle` | `#804000` | `#ff9933` | 2 |
| `network` | Network | `rectangle` | `#003333` | `#00ffff` | 2 |
| `commandline` | Command line | `rectangle` | `#332b00` | `#ffcc00` | 1 |
| `powershell` | PowerShell | `rectangle` | `#4d2e00` | `#ff9900` | 1 |
| `commandline-exec` | Command exec | `rectangle` | `#431407` | `#c2410c` | 1 |
| `alert` | Alert | `star` | `#b30000` | `#ff0000` | 3 |

**Rules**

- To add or recolor a group, edit `NODE_GROUPS` only. The stylesheet
  (`stylesheet()`) and the legend in `GraphView.jsx` derive from it
  automatically. Never hardcode these hex values in another file.
- `commandline-exec` is deliberately darker than `commandline`/`powershell`: it
  marks PowerShell command / command-history artifacts.
- Do not recreate these tokens as CSS variables or Tailwind `@theme` entries;
  that produced a stale, unused duplicate palette in the past.

---

## 3. Typography

Default Tailwind sans (system font stack) for UI; `font-mono` for anything that
is machine output.

| Element | Size | Weight | Notes |
| --- | --- | --- | --- |
| App title ("EDR Analyzer") | `text-xl` | `font-bold` | Sidebar header |
| Panel detail heading | `text-lg` | `font-bold` | Selected element title |
| Section headings | `text-sm` | `font-semibold` + `uppercase tracking-wider` | "Datasets", filter labels |
| Body / controls | `text-xs` | `font-semibold` | Toolbar, tabs, buttons |
| Body / labels | `text-sm` | normal | Dataset names, filter rows |
| Micro labels | `text-[10px]` | `font-bold` | Legend, All/None buttons, hints |
| Raw JSON / evidence | `text-xs` | `font-mono` | `<pre>` blocks |

Graph typography (Cytoscape, not Tailwind): node labels `monospace` **10px**,
edge labels **8px**, both with `min-zoomed-font-size` so they hide when zoomed
out (6 for nodes, 5 for edges).

---

## 4. Spacing & shape

- **Padding:** `p-1.5` (compact inputs), `p-2` (chips, small surfaces), `p-3`
  (cards, JSON blocks), `p-4` (panels/sections).
- **Gaps:** `gap-1`, `gap-1.5`, `gap-2`, `gap-3`; vertical rhythm with
  `space-y-1 / 2 / 4 / 6`.
- **Radius:** `rounded` (default controls, inputs), `rounded-md` (icon buttons),
  `rounded-lg` (dataset cards, dropzone), `rounded-sm` (legend swatches).
- **Borders:** default `border` (slate-200 / dark slate-700); accent dividers
  `border-b-2` (active tab); dropzone `border-2 border-dashed`.
- **Shadows:** `shadow` on toolbar controls, `shadow-lg` on the right pane.
- **Motion:** `transition-colors duration-200` for color changes; `duration-300`
  for pane collapse/expand.

---

## 5. Dark mode

- Enabled by adding `class="dark"` to `<html>` (see `frontend/index.html`).
- Every component provides a `dark:` variant next to its light classes.
- Do not use `prefers-color-scheme` directly; rely on the `.dark` class so the
  theme is explicit and toggleable.

---

## 6. Components

### Auth gate (`frontend/src/components/AuthPage.jsx`)

Full-screen, centered card (`max-w-sm`, `rounded-lg`, `shadow`) on the page
background. Serves both the first-run "create admin" form and the login form.
Inputs and the primary button reuse the shared styles (see Inputs / Buttons).
Errors are inline (`text-xs text-red-600 dark:text-red-400`), never `alert()`.

### Change-password modal (`frontend/src/components/ChangePasswordModal.jsx`)

Overlay (`fixed inset-0`, `bg-black/50`) with a centered `max-w-sm` card. Three
password fields plus Cancel/Save; success swaps in an inline confirmation. Closes
on backdrop click, the `X`, or Cancel. Opened from the sidebar's key button.

### Sidebar (`frontend/src/components/Sidebar.jsx`)

- Width: collapsed `w-16`, expanded `w-80`; `border-r`, `bg-white dark:bg-slate-800`.
- **Upload dropzone:** `border-2 border-dashed rounded-lg`, `bg-slate-50
  dark:bg-slate-700`, hover lightens. Error text below in `text-xs
  text-red-600 dark:text-red-400` (inline, never `alert()`).
- **Dataset card:** `p-3 rounded-lg border cursor-pointer`. Active:
  `bg-blue-50 border-blue-500 dark:bg-blue-900/20 dark:border-blue-400`. Idle:
  `bg-white border-slate-200 hover:border-blue-300` (dark mirrors).
- **Section header:** `text-sm font-semibold uppercase tracking-wider
  text-slate-500 dark:text-slate-400`.
- **Account footer:** the username (`text-xs`, muted) plus a ghost sign-out
  button pinned to the bottom (`border-t`); the collapsed rail shows a sign-out
  icon too.

### Buttons

| Variant | Classes |
| --- | --- |
| Ghost icon | `p-2 rounded-md hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400` |
| Primary | `bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded font-semibold` |
| Danger | `bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800` |
| Warning | `bg-orange-200 dark:bg-orange-800 text-orange-800 dark:text-orange-200` |
| Mini toggle | `text-[10px] bg-slate-200 dark:bg-slate-700 px-2 py-0.5 rounded hover:bg-slate-300 dark:hover:bg-slate-600` |

### Inputs

`w-full bg-slate-50 dark:bg-slate-900 border border-slate-300
dark:border-slate-600 rounded p-2 focus:ring-1 focus:ring-blue-500
outline-none` (compact variants use `p-1.5 text-xs`).

### Toolbar (graph overlay)

`bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600
rounded px-3 py-1.5 text-xs font-semibold shadow` (also used for `<select>`).

### Right pane tabs

Active: `bg-blue-50 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400
border-b-2 border-blue-500`. Idle: `text-slate-500 hover:bg-slate-50
dark:hover:bg-slate-700`.

### Surfaces

- **Filter list container:** `bg-slate-50 dark:bg-slate-900 border
  border-slate-200 dark:border-slate-700 rounded`, `max-h-40` scrollable.
- **Raw-log block:** `bg-slate-100 dark:bg-slate-900 rounded border font-mono
  text-xs`.
- **Element title `<pre>`:** `bg-slate-50 dark:bg-black p-3 rounded border
  font-mono text-xs text-slate-700 dark:text-green-400`.
- **Info banner:** orange surface (`bg-orange-50 dark:bg-orange-900/20`) with
  matching border.
- **Legend overlay:** `bg-white/90 dark:bg-slate-800/90 backdrop-blur border
  rounded p-2 shadow text-[10px]`, `pointer-events-none`.

### Scrollbars

Use `custom-scrollbar` on scrollable regions. It renders a 6px track, thumb
`#cbd5e1` (light) / `#475569` (dark), defined in `frontend/src/index.css`.

---

## 7. Graph styles (Cytoscape)

Defined in `frontend/src/components/cytoscapeStyles.js`.

- **Nodes:** label-driven size (`width/height: label`, `padding: 12px`), white
  text, `border-width: 2`, per-group shape/color from `NODE_GROUPS`.
- **Edges:** `width: 2`, `curve-style: bezier`, `target-arrow-shape: triangle`,
  color from element data (`line-color` / `target-arrow-color: data(color)`),
  label with `text-background-color: #222`.
- **Dashed edges:** `.dashed` class → `line-style: dashed`.
- **Hidden:** `.hidden` → `display: none` (used by filters).
- **Spotlight:** `.dimmed` → `opacity: 0.12` (selected neighbourhood only).
- **Selection:** selected node gets a `#ffffff` border of width 4 and
  `overlay-opacity: 0`; selected edge width 4.

---

## 8. Icons

`lucide-react` only. Standard sizes: `14` (inline/copy), `16` (row actions),
`20` (pane toggles), `24` (primary nav). Color via Tailwind `text-*` classes.

---

## 9. Conventions & invariants

1. New graph node type → add one entry to `NODE_GROUPS` (color + shape + label);
   the stylesheet and legend update themselves.
2. Never duplicate a hex color in a second file. If a color is needed in both
   JS and CSS, expose it from the JS source of truth.
3. Every new component ships light **and** `dark:` classes.
4. Prefer semantic Tailwind roles over raw hex in JSX. Raw hex is acceptable
   only inside Cytoscape style definitions and `#222`/`#222`-like canvas
   backgrounds.
5. Add `custom-scrollbar` to any new scroll container.
6. Keep focus states visible (`focus:ring-1 focus:ring-blue-500`) for
   accessibility.
