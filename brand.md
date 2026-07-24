# Brand — TerminalX

_Status: deferred_

The user chose to defer a formal brand redesign. Preserve TerminalX's existing dark-only SuperTerminal system: near-black layered surfaces, JetBrains Mono, phosphor green as the sparse signal color, amber for attention, cyan for information, and red for destructive actions. The canonical tokens live in `src/app/globals.css`.

The `frontend-design-guidelines` skill should use that established baseline and should not prompt again.

To set up a real brand palette, typography, and voice at any time, run:

    /brand-design

or say: "pick brand colors"

When `brand-design` runs, it will detect this deferred state, skip the "confirm overwrite" step, and proceed directly to the full brand setup. The resulting palette will be applied to `app/globals.css` and this file will be replaced with the real brand documentation.

_Deferred at: 2026-07-23T18:09:21Z_
