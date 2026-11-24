# OpenKeylet UI Design System

> **Single Source of Truth** for OpenKeylet desktop (`renderer/*`) and browser extension (`browser-extension/*`) interfaces.  
> Companion specification: [control-geometry.md](control-geometry.md) (recessed hardware geometry & contrast invariants).

---

## 1. Visual Philosophy — Pure Monochrome Carbon & Porcelain

- **Restrained industrial minimalism**: Pure neutral monochrome palette with zero blue/purple hue cast.
  - **Dark (Carbon)**: `--canvas: #070708`, `--surface-1 / --surface-2: #111114`, `--surface-3: #1b1b1f`, `--surface-input: #0b0b0d`, `--ink: #f4f4f5`, `--muted: #a1a1aa`, `--faint: #71717a`.
  - **Light (Porcelain)**: `--canvas: #f7f7f8`, `--surface-1: #ececef`, `--surface-2: #ffffff`, `--surface-3: #f2f2f4`, `--ink: #111114`, `--muted: #52525b`, `--faint: #8a8a94`.
- **Semantic color discipline**: Chromatic colors (`--success`, `--warn`, `--danger`) are reserved strictly for live status dots, validation alerts, and destructive actions—never for decorative fills or branding gradients.
- **Dark & Light parity**: Every new surface, border, badge, and icon MUST use CSS tokens (`var(--...)`) so both themes remain legible and high-contrast without one-off hardcoded hex colors.
- **No unnecessary chrome**: Modal headers and footers are borderless (`border-bottom: 0; border-top: 0;`), relying on spacing rhythm and surface hierarchy rather than divider lines.

---

## 2. Strict 4px / 8px Grid & Spacing Scale

Every layout dimension, padding, and gap must resolve cleanly onto the **4px sub-grid / 8px primary grid** (whole physical pixels at 100%, 125%, 150%, and 200% DPI scaling):

| Token | Value | Usage |
| :--- | :---: | :--- |
| `--control-inset` | `4px` | Inner clearance inside segmented wells, switch tracks, tight card list gaps (`4px`), label-to-input gaps (`4px`) |
| `--region-gap` | `8px` | Primary spacing between regions, buttons, grid columns, modal backdrop padding (`8px`), section vertical rhythm |
| `--shell-inset` | `12px` | **Authoritative horizontal content rail** for the main window shell AND all modal headers, bodies, and footers |
| `16px` | `16px` | Standalone alert/confirm dialog padding (`.confirm-card`) and large section breathing room |

### Alignment Rail Rule (Mandatory)
- Within any window or modal card, the **left edge of the header title mark, the left edge of body fields/cards, and the left edge of footer copy/actions MUST share the exact same `12px` (`--shell-inset`) rail**; likewise the **right edge of the header close button, body controls, and footer primary button MUST align on the same `12px` right rail**.
- Never mix `10px`, `14px`, and `16px` horizontal paddings across header/body/footer of the same dialog.

---

## 3. Corner Radius Hierarchy (Concentric Step-Down)

Radii step down monotonically from outer container to inner element so nested curves look concentric and rectilinear:

| Token | Value | Usage |
| :--- | :---: | :--- |
| `--window-radius` | `8px` | Top-level desktop window frame & modal backdrop clip |
| `--radius-lg` | `10px` | Modal cards (`.modal-card`, `.confirm-card`), primary floating sheets, dropdown menus |
| `--radius` | `8px` | Cards/rows inside a modal or list (`.connection-card`, `.module-row`, `.settings-card`, `.mvault-item-row`), segmented tracks, standard buttons |
| `--radius-sm` | `6px` | Travelling caps/thumbs inside wells, compact inputs, icon buttons (`24px`–`28px`), switches, inline alert boxes |
| `--radius-xs` | `4px` | Small chips, mono badges/pills, checkboxes, compact key tags |

- Avoid mixing `border-radius: 999px` pills alongside `--radius-xs` (`4px`) rectangular badges in the same metadata row; prefer `--radius-xs` (`4px`) for technical/mono metadata chips.

---

## 4. Control Heights & Density Budget

| Token | Value | Usage |
| :--- | :---: | :--- |
| `--switch-height` | `24px` | Binary ON/OFF switches (`.switch`, `.module-agent-toggle`), compact module action icon buttons (`24×24px`), inline custom field name inputs |
| `--compact-control-height` | `28px` | Modal text inputs, selects, inline helper buttons (`+ 添加模块`, `生成密码`, `SHOW`), modal header close button (`28×28px`) |
| `--control-height` | `32px` | Top titlebar wells, primary nav bar, filter strips, primary modal footer buttons (`保存` / `关闭` / `确认`), single-line option strips |

### High-Density Ergonomics Target (460 × 690 Desktop Frame)
- **Information density first**: Avoid multi-line bloat cards for single boolean toggles or redundant helper banners.
- In list-heavy editors (such as `#connection-modal` item modules and `.mvault` checklists), **at least 4–5 complete rows MUST fit in one viewport at default height (`690px`)** without vertical scrolling.
- Keep auxiliary actions (e.g., Password `Generate`, `SHOW` reveal button) inline on the same row as their input (`height: 28px`) rather than stacking a second row beneath the field.

---

## 5. Typography & Hierarchy

- **UI Sans (`--sans`)**: `"Inter", "Segoe UI Variable", "Segoe UI", "PingFang SC", "Microsoft YaHei UI", -apple-system, BlinkMacSystemFont, sans-serif` (macOS: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", sans-serif`).
- **Technical Mono (`--mono`)**: `"JetBrains Mono", "Cascadia Mono", "SFMono-Regular", Consolas, monospace` — used strictly for status codes, endpoints, counts, field keys, version pills, and secret inputs.
- **Numeric alignment**: Root sets `font-variant-numeric: tabular-nums; font-synthesis: none;`.

| Role | Font | Size | Weight | Line-height | Color |
| :--- | :--- | :---: | :---: | :---: | :--- |
| Modal / Dialog Title (`h2`) | `--sans` | `13px` (confirm: `14px`) | `600` | `1.25` | `--ink` |
| Section Heading | `--sans` | `12px` | `600` | `1.3` | `--ink` |
| Input / Body / Primary Button | `--sans` | `11.5px` | `400`–`600` | `1.45` | `--ink` |
| Field Label / Helper Copy | `--sans` | `11px` | `500` / `400` | `16px` / `1.45` | `--muted` |
| Secondary Hint / Footer Note | `--sans` | `10px` | `400` | `1.35` | `--faint` |
| Mono Badges / Status / Keys | `--mono` | `9.5px` | `600` | `1.25` | `--muted` / `--faint` |

- Always apply `min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;` on single-line titles, labels, and badges to guarantee **zero horizontal overflow** across all 6 supported languages (`en`, `zh`, `zh-TW`, `ja`, `ko`, `es`).

---

## 6. Icon System & Alignment

- **Rendering & Centering**:
  - Every icon container button MUST use `display: inline-grid; place-items: center; padding: 0;`.
  - Every `<svg>` icon MUST set `display: block;` (preventing inline baseline descender offset).
- **Stroke Style**:
  - Uniform monochrome line-art: `fill: none; stroke: currentColor; stroke-linecap: round; stroke-linejoin: round;`.
  - Stroke width: `1.75`–`1.8` on `16×16` / `20×20` / `24×24` viewBoxes.
- **Sizes**:
  - Header & action icon buttons: `14×14px` (`--header-icon-size`) inside `28×28px` (header) or `24×24px` (compact row action) hit targets.
  - Confirmation / empty-state icon badges: `16×16px` inside `32×32px` container.
- **Close Buttons**: Every modal close button MUST use the unified `<svg viewBox="0 0 16 16"><path d="m4 4 8 8m0-8-8 8"/></svg>` SVG—never raw text `×` characters.

---

## 7. Unified Interaction, Drag & Audio Language

### A. Draggable Window Headers (Desktop App)
- Every modal `.modal-header` (and `.confirm-card`) MUST carry `data-tauri-drag-region="deep"` and CSS `-webkit-app-region: drag; user-select: none;`.
- Non-interactive header text/marks set `pointer-events: none; -webkit-user-drag: none;`.
- Every interactive control inside a header (`button`, `input`, `select`, `a`, `label`, close button) MUST carry `data-tauri-drag-region="false"` and `-webkit-app-region: no-drag;`.

### B. Lifted-Card FLIP Drag-to-Reorder (Homepage & Module Editor)
- **No clunky `⋮⋮` drag-handle columns**: Users reorder cards directly by **dragging (`≥ 6px`) or long-pressing (`240ms`)** anywhere on the card surface outside interactive controls (`input`, `textarea`, `select`, `button`, switches, action icons).
- **Visual physics** (identical across `#connections-list` and `#module-list`):
  1. Clone the real card (preserving live input values) into a `position: fixed; z-index: 2000; pointer-events: none;` preview host styled with `.is-lifted-card` (`border-color: var(--accent)`, `box-shadow: var(--shadow-float), 0 0 0 1px var(--accent-ring)`, `transform: scale(1.018)`).
  2. Mark the original slot as a dashed ghost (`opacity: 0.14; border-style: dashed; border-color: var(--border-strong);` with hidden children).
  3. Apply subtle horizontal damping (`clamp((x - startX) * 0.12, -10, 10)`) for vertical lists, **FLIP transform transitions (`180ms cubic-bezier(0.22, 1, 0.36, 1)`)** on displaced siblings, and smooth edge auto-scrolling.
  4. Preserve keyboard accessibility (`tabindex="0"` + `ArrowUp` / `ArrowDown` with live status announcement).

### C. Sound Feedback Discipline
- Interface sounds default to **ON**, triggered only on deliberate actions (click, toggle, select/lift, drop, success, error).
- **Never play hover sounds** (`pointerover` / `hover` must remain completely silent).

---

## 8. Pre-Merge UI Checklist

Before finalizing any UI change, verify all items:
1. All margins, paddings, and gaps follow the **4px / 8px grid**; modal header, body, and footer align on the **`12px` (`--shell-inset`)** left/right rails.
2. Radii follow **`10px` modal -> `8px` card/row -> `6px` button/input -> `4px` badge/checkbox**.
3. Heights follow **`24px` / `28px` / `32px`** tokens; inline input+button pairs have identical heights.
4. All icons use unified monochrome SVG strokes centered with `inline-grid; place-items: center;` and `display: block;` (no raw text `×`).
5. Every modal header supports native Tauri window dragging (`data-tauri-drag-region="deep"`).
6. List/editor views display **4–5 rows per screen** without wasted vertical whitespace and **zero horizontal overflow** across all 6 languages (`en`, `zh`, `zh-TW`, `ja`, `ko`, `es`) in both **Dark** and **Light** themes.
7. CSS braces balance and `node --check` passes on all modified JS files.
