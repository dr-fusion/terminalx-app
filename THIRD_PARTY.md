# Third-Party Notices

This file lists third-party software distributed with TerminalX (either
vendored in-tree or declared as runtime dependencies) along with their
licenses. Only **bundled / vendored** code needs attribution here; normal
`node_modules` licenses are discoverable via `npm ls --all --long` and
are reproduced in published artifacts.

## Vendored packages

The following `@wterm/*` tarballs are vendored in `vendor/wterm/` and
installed from disk rather than npm. They are redistributed under the
Apache License 2.0.

| Package            | Version | License    | Upstream                             |
| ------------------ | ------- | ---------- | ------------------------------------ |
| `@wterm/core`      | 0.1.8   | Apache-2.0 | https://github.com/vercel-labs/wterm |
| `@wterm/dom`       | 0.1.8   | Apache-2.0 | https://github.com/vercel-labs/wterm |
| `@wterm/just-bash` | 0.1.8   | Apache-2.0 | https://github.com/vercel-labs/wterm |
| `@wterm/markdown`  | 0.1.8   | Apache-2.0 | https://github.com/vercel-labs/wterm |
| `@wterm/react`     | 0.1.8   | Apache-2.0 | https://github.com/vercel-labs/wterm |

Full license text is preserved inside each tarball at
`package/LICENSE`. Extract with:

```bash
tar -xzOf vendor/wterm/wterm-core-0.1.8.tgz package/LICENSE
```

## Other notable dependencies

These are not vendored but are central to TerminalX's functionality.
License information is embedded in each package and reproduced in the
runtime `node_modules` tree.

- **node-pty** (MIT) — PTY bindings for Node.js
- **xterm.js** (MIT) — terminal emulator
- **Next.js** (MIT) — application framework
- **React** (MIT) — UI framework
- **ws** (MIT) — WebSocket server
- **jose** (MIT) — JWT signing / verification
- **bcryptjs** (MIT) — password hashing
- **chokidar** (MIT) — file watcher
- **shadcn/ui** (MIT) — component primitives
- **Tailwind CSS** (MIT) — styling
- **Lucide** (ISC) — iconography

For the complete, machine-generated dependency manifest, run:

```bash
npx license-checker --production --summary
```
