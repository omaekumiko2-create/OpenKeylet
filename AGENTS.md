# Repository Guidelines for AI Agents

## Mandatory UI & Design System Compliance

**Before making ANY change to desktop UI (`renderer/*`) or browser extension UI (`browser-extension/*`), you MUST read and strictly follow:**

1. [`docs/UI_DESIGN_SYSTEM.md`](docs/UI_DESIGN_SYSTEM.md) — Authoritative OpenKeylet UI Design System (Carbon & Porcelain monochrome palette, 4px/8px grid, `12px` alignment rails, concentric corner radii, control height tokens, typography scale, SVG icon standards, draggable modal headers, homepage-style lifted-card FLIP drag-to-reorder, and audio rules).
2. [`docs/control-geometry.md`](docs/control-geometry.md) — Recessed control geometry, switch state cues, and contrast invariants.

### Non-Negotiable UI Rules
- **Grid & Rail Discipline**: All spacing must be multiples of `4px` / `8px` using `:root` tokens (`--control-inset: 4px`, `--region-gap: 8px`, `--shell-inset: 12px`). Modal headers, bodies, and footers must share the exact `12px` horizontal rail and consistent card width (`min(444px, 100%)` for standard dialogs).
- **Radius Discipline**: Strictly use `--radius-lg` (`10px`) -> `--radius` (`8px`) -> `--radius-sm` (`6px`) -> `--radius-xs` (`4px`). Do not invent arbitrary radii or mix pill (`999px`) badges next to rectilinear chips.
- **Control Heights**: Use `--switch-height` (`24px`), `--compact-control-height` (`28px`), and `--control-height` (`32px`). Inline input + button pairs must match heights exactly.
- **Icon Discipline**: Center all icon buttons with `display: inline-grid; place-items: center; padding: 0;` and `svg { display: block; fill: none; stroke: currentColor; stroke-linecap: round; stroke-linejoin: round; }`. Never use raw text `×` for modal close buttons.
- **Interaction & Drag Parity**:
  - Every desktop modal header MUST support native Tauri window dragging (`data-tauri-drag-region="deep"`, interactive children marked `data-tauri-drag-region="false"`).
  - Reorderable card lists MUST use homepage-style **whole-card lifted-card FLIP drag-to-reorder** (no `⋮⋮` drag-handle columns).
  - Never add hover sound effects.
- **Density & Localization**: Editors and list dialogs must stay compact and high-efficiency (**4–5 full rows visible per screen** at default `460×690` window size), with zero horizontal overflow across all 6 languages (`en`, `zh`, `zh-TW`, `ja`, `ko`, `es`) in both Dark and Light themes.
- **Desktop vs. Browser Extension Boundary**: The desktop app is the single vault management center; the browser extension is a least-privilege **Agent Browser Bridge & Current-Site Autofill** channel and must not duplicate full vault CRUD, trash, history, or standalone generator UI.

## Verification

- Always verify modified JS with `node --check`, verify CSS brace balance, and run relevant `cargo test` suites before finishing.
- On Windows with SMB workspaces, run Cargo with the local `CARGO_TARGET_DIR` (loaded via `Use-ProjectEnvironment.ps1` or `scripts/dev-hot.ps1`).
