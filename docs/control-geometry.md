# Recessed control geometry

OpenKeylet uses a recessed-well hardware geometry: a recessed floor surrounds
raised caps, with one inset used on every edge. OpenKeylet uses a compact
32 px primary row and derives a 24 px cap from the same 4 px inset.
Item rows and single-line editor fields use the compact 28 px control token.
Item action caps derive their 20 px height from that token and the same inset;
the bordered item row is 38 px tall. Compact density changes control size and
section spacing, while preserving the existing text sizes and state cues.

- Define dimensions through the tokens in `renderer/styles/tokens.css`.
  `--control-inset` governs all four clearances; cap sizes and switch widths are
  derived from the row height and travel. Do not override one edge independently.
- A well owns its padding and floor. Its children must fit the content box,
  including their borders. A travelling cap uses the same inset at both ends.
- Theme changes alter materials, not geometry. The LCD digit height is separate
  from the control cap height because digits are readout content, not buttons.
- Keep the shared shallow floor and restrained contact shadow. Do not use extra
  borders or asymmetric padding to compensate for shadows.
- SYSTEM sections use the shared raised panel face with `--region-gap` padding
  and `--well-inset` spacing. Labels remain on that face; readouts, inputs and
  action wells use the shared recessed material. Avoid decorative module-number
  rows, nested list wells and separate status-badge backgrounds.
- Each settings action has its own `.command-well`, with a standard-height cap
  and four equal insets. Action groups may wrap between wells, never inside one.
  Hide the well with a hidden action to avoid empty pits during state changes.
- Use the existing drag-preview selector with sufficient specificity to override
  checked-state positioning. Clicked and dragged endpoints must coincide.

## State language

- Keep the well floor and raised cap materials constant across states.
- Selected and enabled states use `--state-active-ink`, derived from the current
  theme accent. Ordinary actions use that same accent on interaction. Red is for
  destructive actions and errors; closing a dialog is an ordinary action.
- Inactive controls use readable `--state-inactive-ink`. Disabled controls use
  `--state-disabled-ink` and do not emit light. Hover never changes an OFF label
  into an ON signal.
- Binary switches share their dimensions and three redundant state cues: ON/OFF
  text, a check/minus glyph and cap position. Their compact height stays 24 px;
  the same 4 px rim surrounds the cap at either endpoint.
- Module permissions also show a persistent localized `AGENT VISIBLE` or
  `AGENT HIDDEN` caption. This describes Agent access, independently of whether
  the owner reveals a password in the editor. Keep the caption, accessible name
  and saved `agentVisible` value synchronized on click, drag and keyboard input.

The standard 4 px inset resolves to whole physical pixels at 100%, 125%, 150%
and 200% display scaling. Fractional grid tracks may still round internally.

Run `npm run test:controls` after loading the project's environment
with `Use-ProjectEnvironment.ps1`. Its `fixtures/control-geometry.mjs` audit checks
rendered child bounds, generated cap bounds, both endpoints and the midpoint. It
covers header controls, navigation, filters, row actions, add/draft controls,
editor controls and settings switches. The header matrix covers both languages,
both themes and all four display scales. Reports and screenshots are written
under the configured myenv temporary directory.

`fixtures/control-states.mjs` checks the visible words, glyphs, localized Agent
captions and state colors, including disabled controls. ON and OFF labels must
have at least 4.5:1 contrast against their well. The interaction suite also checks
caption updates after dragging, Space and Enter, shared ordinary-action ink,
distinct destructive-action ink and unchanged floor material across states.
