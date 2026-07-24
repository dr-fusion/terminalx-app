# TerminalX Custom AI Providers / Harnesses — Specification

**Status:** Design Specification (rewrite, grounded in Conductor screenshots)
**Date:** 2026-06-25
**Backs GitHub issue:** #4
**Conductor analog:** Settings → **Harnesses** page (Claude Code / Codex / Cursor / OpenCode[NEW] tabs) + the **Providers** picker reached from the OpenCode tab.

> **Safety correction (2026-07-23):** The LocalTmux implementation no longer
> exposes or consumes `dangerouslySkipPermissions`, and Codex no longer starts
> with `--yolo`. The correction in `00-corrections.md` supersedes the older
> payload, UI, `optionFlags`, and command examples retained below as design
> history.

---

## 0. Summary

TerminalX currently hard-codes its AI runtimes as a closed `SessionKind = "bash" | "claude" | "codex"` union, with a parallel `CLI_BINS` table and a `commandForKind()` switch in `src/lib/ai-sessions.ts`. Adding a runtime today means editing the type, the lookup table, the command builder, the API validator, the dashboard toggle, and the `useSessions` hook in lockstep.

This spec replaces that with a **harness/provider registry**: a data-driven list of AI runtimes ("harnesses" in Conductor's vocabulary), each declaring its CLI binary, authentication strategy, and command template. It mirrors Conductor's **Harnesses** settings page — per-harness tabs, CLI-vs-API-key authentication with a "Connected" status table, and an **OpenCode** harness that owns a nested **Providers** registry (the "Add your first provider" flow with 96 upstream providers). The registry is the single source of truth that the dashboard, the settings UI, and the session API all read from.

This is explicitly **not** the invented multi-provider HTTP-wrapper design from the prior draft (no `AIProvider` class hierarchy, no `data/provider-credentials/` store, no OpenAI/Gemini/Ollama HTTP REPLs). Those contradicted the real Conductor UI and the real TerminalX architecture; see `00-corrections.md` for the per-document audit.

---

## 1. Conductor UI reference (from screenshots)

These are the authoritative UI facts this feature mirrors. TerminalX naming differs (`.terminalx/`, `TERMINALX_*`); the Conductor analog is named in each row.

### 1.1 Settings shell

- Two top-level scope tabs: **User** and **Repo**. Settings exist at both scopes.
- User-scope left nav: General, Account, **Models**, **Harnesses** (a **Providers** entry appears in one capture), Environment, Git, Appearance; then a **More** group: Experimental, Advanced.
- Repo-scope harness screens have a top-right **"Edit settings.toml"** button — repo config lives in a committed `.conductor/settings.toml`.

### 1.2 Harnesses page

- Title **"Harnesses"**. Sub-tabs, **one per harness**: **Claude Code**, **Codex**, **Cursor**, **OpenCode** (the last carries a **"NEW"** badge).

**Claude Code tab:**

- **Authentication** section: two large mutually-exclusive choices — **"CLI"** (terminal icon, shows a ✓ when active) vs **"API key"** (key icon).
- A green **"Connected"** pill.
- A table: **Provider** = "Anthropic API", **Plan** = "Max", **Org** = `<name>`, **Account** = `<email>`.
- A **"Run claude /login"** button (play icon).
- A **"Use Claude Code with Chrome"** subsection with extension + docs links.

**OpenCode tab:**

- Header row: **"OpenCode — The open source AI coding agent"** + a **"Docs ↗"** link.
- **"Providers 0 configured"** with an **"Add your first provider"** button.
- **"Models 0 selected"** with an **"Add your first OpenCode model"** button.
- Collapsible **"Advanced"**: a green **"Installed 1.17.7"** pill, **"Open in Finder ↗"**, **"Docs ↗"**, **"Refresh"**.
- **"OpenCode executable path"** field, placeholder `/usr/local/bin/opencode`, helper text: _"Override the bundled OpenCode executable with a custom one. Leave empty to use the bundled version (recommended)."_

### 1.3 Provider picker modal (from OpenCode → "Add your first provider")

- Modal titled **"Providers"** with a **"Search providers"** input.
- Provider rows, each a brand icon + expandable detail: **OpenCode Go / OpenCode Zen**, **OpenAI**, **GitHub Copilot / GitHub Models**, **Anthropic**, **Google**, **Vercel AI Gateway**, **OpenRouter**.
- Footer: **"View all providers (96)"**. The canonical list is these named rows; the total is **96**. (Do not invent "ChatGPT/Gemini/Ollama" as the canonical list.)

### 1.4 Models page (related, owned by a sibling spec)

- "Default model" and a **separate, independently-configurable "Review model"** (code review uses its own model). Provider/harness selection here is downstream of the registry this spec defines.

---

## 2. Scope of this spec

**In scope:**

1. A harness/provider **registry** data model that replaces `CLI_BINS` / `commandForKind()` / `isValidKind()` in `src/lib/ai-sessions.ts`.
2. Per-harness **authentication descriptors** (CLI vs API key) and a status probe that produces the "Connected" + Provider/Plan/Org/Account table data.
3. The **OpenCode harness** as a special case: it is itself a host for a nested **provider** registry (the 96-provider picker), plus install detection, version display, and an executable-path override.
4. A **Harnesses settings surface** in `SettingsView.tsx` and a **harness selector** in `DashboardView.tsx`, both reading the registry.
5. A new **`GET/POST /api/harnesses`** route family, and the changes to **`POST /api/sessions`** to accept a harness id.
6. A committed **`.terminalx/settings.toml`** (Conductor's `.conductor/settings.toml` analog) for repo-scoped harness config, with User-vs-Repo scope split.

**Out of scope (owned elsewhere / explicitly deferred):**

- Per-model selection / the Models page (sibling spec; this spec only exposes which harnesses exist).
- Secret encryption at rest beyond file-mode 0600 (TerminalX is env-driven today; see §6.3).
- HTTP/REST chat wrappers for cloud APIs — TerminalX runs **CLIs in tmux**, not in-process REPLs. The "providers" inside OpenCode are configured by writing OpenCode's own config; TerminalX does not proxy them.

---

## 3. Data model

### 3.1 Current state (verified in repo)

`src/lib/ai-sessions.ts`:

```typescript
export type SessionKind = "bash" | "claude" | "codex";

const CLI_BINS: Record<SessionKind, string | null> = {
  bash: null,
  claude: "claude",
  codex: "codex",
};

export function commandForKind(kind: SessionKind, opts: CommandOptions = {}): string | null {
  const bin = CLI_BINS[kind];
  if (!bin) return null;
  const args: string[] = [];
  if (kind === "claude" && opts.dangerouslySkipPermissions) {
    args.push("--dangerously-skip-permissions");
  }
  const invocation = [bin, ...args].join(" ");
  return `bash -lc '${invocation}; ec=$?; echo; echo "[${bin} exited with code $ec — dropping to bash]"; exec bash -l'`;
}

export function isValidKind(kind: unknown): kind is SessionKind {
  return kind === "bash" || kind === "claude" || kind === "codex";
}
```

`SessionKind` is **also independently declared** in `src/hooks/useSessions.ts` (line 5) — both must move to the registry's exported type to stay in sync.

### 3.2 Harness descriptor

New file `src/lib/harnesses/types.ts`. A **harness** is a CLI runtime that drives a tmux session. `bash` remains a harness with no binary (the always-available fallback). This keeps `SessionKind`'s open set small and serializable into `SessionMeta.kind` — existing `ai-sessions.json` records stay valid.

```typescript
// src/lib/harnesses/types.ts

/** Authentication strategy mirrored from Conductor's Claude Code tab. */
export type HarnessAuthMethod = "cli" | "api-key" | "none";

/** How the session command is built. */
export interface HarnessCommandSpec {
  /** Binary resolved from PATH, e.g. "claude". null => plain login shell (bash). */
  bin: string | null;
  /** Extra args appended unconditionally. */
  baseArgs?: string[];
  /**
   * Flags that are conditionally appended from CommandOptions.
   * Keeps the `--dangerously-skip-permissions` special-case data-driven
   * instead of a hard-coded `kind === "claude"` check.
   */
  optionFlags?: Array<{
    /** key in CommandOptions that gates this flag */
    when: keyof CommandOptions;
    flag: string;
  }>;
}

export interface HarnessDescriptor {
  /** Stable id, persisted as SessionMeta.kind. e.g. "bash" | "claude" | "codex" | "opencode". */
  id: string;
  /** Tab/button label, e.g. "Claude Code", "Codex", "Cursor", "OpenCode". */
  label: string;
  /** Conductor-style "NEW" badge on the tab. */
  badge?: "NEW";
  /** Theme color used by the dashboard toggle + session-row chip. */
  color: string;
  /** Authentication descriptor surfaced in the settings tab. */
  auth: HarnessAuthMethod;
  /** Command-builder spec. */
  command: HarnessCommandSpec;
  /**
   * Marks the OpenCode-style harness that hosts a nested provider registry
   * + install/version detection + executable-path override (see §5).
   */
  hostsProviders?: boolean;
  /** Docs link shown in the harness tab header (Conductor "Docs ↗"). */
  docsUrl?: string;
}

export interface CommandOptions {
  /** claude-only today; data-driven via optionFlags. */
  dangerouslySkipPermissions?: boolean;
}
```

### 3.3 Built-in harness table

New file `src/lib/harnesses/registry.ts`. This **is** the new `CLI_BINS`/`commandForKind` source of truth.

```typescript
// src/lib/harnesses/registry.ts
import type { HarnessDescriptor, CommandOptions } from "./types";

export const HARNESSES: HarnessDescriptor[] = [
  {
    id: "bash",
    label: "bash",
    color: "#00cc6e",
    auth: "none",
    command: { bin: null },
  },
  {
    id: "claude",
    label: "Claude Code",
    color: "#d58fff",
    auth: "cli", // CLI (claude /login) or API key (ANTHROPIC_API_KEY)
    docsUrl: "https://docs.claude.com/claude-code",
    command: {
      bin: "claude",
      optionFlags: [{ when: "dangerouslySkipPermissions", flag: "--dangerously-skip-permissions" }],
    },
  },
  {
    id: "codex",
    label: "Codex",
    color: "#5ccfe6",
    auth: "cli",
    command: { bin: "codex" },
  },
  {
    id: "cursor",
    label: "Cursor",
    color: "#7dd3fc",
    auth: "cli",
    command: { bin: "cursor-agent" },
  },
  {
    id: "opencode",
    label: "OpenCode",
    badge: "NEW",
    color: "#ffa657",
    auth: "none", // auth lives inside OpenCode's own per-provider config
    hostsProviders: true,
    docsUrl: "https://opencode.ai/docs",
    command: { bin: "opencode" },
  },
];

const BY_ID = new Map(HARNESSES.map((h) => [h.id, h]));

export function listHarnesses(): HarnessDescriptor[] {
  return HARNESSES;
}

export function getHarness(id: string): HarnessDescriptor | undefined {
  return BY_ID.get(id);
}

/** Replaces the old isValidKind(). */
export function isValidHarnessId(id: unknown): id is string {
  return typeof id === "string" && BY_ID.has(id);
}
```

> Naming note: Conductor calls Anthropic's harness "Claude Code". TerminalX's persisted id stays `"claude"` for backward compatibility with existing `SessionMeta` records and the Telegram topic table; only the **label** is "Claude Code".

### 3.4 Command builder (replaces `commandForKind`)

```typescript
// src/lib/harnesses/command.ts
import { getHarness } from "./registry";
import type { CommandOptions } from "./types";

/**
 * Build the tmux session command for a harness id.
 * Returns null for harnesses with no binary (bash), matching the
 * existing `commandForKind` contract used by createSession().
 */
export function commandForHarness(id: string, opts: CommandOptions = {}): string | null {
  const h = getHarness(id);
  if (!h || h.command.bin === null) return null;

  const args = [...(h.command.baseArgs ?? [])];
  for (const { when, flag } of h.command.optionFlags ?? []) {
    if (opts[when]) args.push(flag);
  }

  const bin = h.command.bin;
  const invocation = [bin, ...args].join(" ");
  // Identical fallback-to-bash wrapper as today (keeps tmux session alive).
  return `bash -lc '${invocation}; ec=$?; echo; echo "[${bin} exited with code $ec — dropping to bash]"; exec bash -l'`;
}
```

This preserves the **exact** existing shell wrapper (single-quoted `bash -lc`, exit-code capture, `exec bash -l` fallback) verified in `commandForKind`. The only behavioral change is that `--dangerously-skip-permissions` is now declared in data (`optionFlags`) instead of an inline `kind === "claude"` branch.

### 3.5 Backward-compat shim

`src/lib/ai-sessions.ts` re-exports from the registry so nothing else breaks during migration:

```typescript
// src/lib/ai-sessions.ts (additions/replacements)
export type SessionKind = string; // open set; was "bash" | "claude" | "codex"

export { isValidHarnessId as isValidKind } from "./harnesses/registry";
export { commandForHarness as commandForKind } from "./harnesses/command";
export type { CommandOptions } from "./harnesses/types";
```

`SessionMeta` is unchanged structurally — `kind: SessionKind` now just accepts the open id set. `src/hooks/useSessions.ts` must `import type { SessionKind }` from a shared client-safe location (e.g. re-export the id list as a value `HARNESS_IDS` consumed by both server and client) instead of redeclaring the union.

---

## 4. Harness authentication & status ("Connected" table)

Conductor's Claude Code tab shows: **CLI vs API key** choice, a **Connected** pill, and a **Provider / Plan / Org / Account** table, plus a **"Run claude /login"** button. TerminalX models this as a read-only status probe per harness (it does **not** store the user's API key; auth is delegated to the CLI exactly as today).

### 4.1 Status probe

```typescript
// src/lib/harnesses/status.ts
import { execFileSync } from "child_process";
import { getHarness } from "./registry";

export interface HarnessStatus {
  id: string;
  installed: boolean; // binary resolvable on PATH
  binPath?: string; // `command -v` result
  version?: string; // best-effort `<bin> --version`
  connected: boolean; // auth present (CLI logged-in OR api-key env set)
  authMethod: "cli" | "api-key" | "none";
  /** Maps to the Conductor Provider/Plan/Org/Account table; fields are best-effort. */
  account?: {
    provider?: string; // "Anthropic API"
    plan?: string; // "Max"
    org?: string;
    account?: string; // email
  };
  /** The login command surfaced by the "Run <cli> /login" button. */
  loginCommand?: string; // e.g. "claude /login"
}

export function probeHarness(id: string): HarnessStatus {
  /* ... */
}
```

Probe rules (all best-effort, never throwing into the request path):

- **installed**: `command -v <bin>` succeeds (POSIX, same approach the repo already uses for binaries). `bash` is always installed.
- **version**: parse `<bin> --version` with a 2s timeout; used for the green "Installed x.y.z" pill (OpenCode) and informational display elsewhere.
- **connected / authMethod**:
  - `auth: "cli"` harness → connected if the CLI reports a logged-in session. For `claude`, also connected if `ANTHROPIC_API_KEY` is set (the "API key" choice). The chosen path drives the ✓ on the CLI vs API key toggle.
  - `auth: "none"` (bash, opencode) → `connected: true` (no harness-level auth; OpenCode auth is per-provider).
- **account**: populated only when the CLI exposes it cheaply; otherwise the table renders dashes. We do **not** invent values.
- **loginCommand**: `"<id-or-cli> /login"` for CLI-auth harnesses (mirrors "Run claude /login"). The button **does not** run a hidden shell; it opens/creates a tmux session running that command, reusing the existing session-creation path so output is visible and the user can complete device-flow login.

### 4.2 No secret storage

The prior draft proposed `data/provider-credentials/credentials.json`. **Removed.** TerminalX delegates auth to each CLI (`~/.claude`, `~/.codex`, OpenCode's own config) and to environment variables (`ANTHROPIC_API_KEY`, etc.), consistent with the existing env-driven config model (`TERMINUS_*`, `TERMINALX_WORKTREES_ROOT`). API keys entered in the "API key" tab are written to the **repo or user `.env`** that sessions already source — not to a bespoke encrypted vault.

---

## 5. The OpenCode harness (nested provider registry)

OpenCode is the one harness that `hostsProviders`. Its tab is not a single auth toggle; it is a mini-manager mirroring the screenshot exactly.

### 5.1 OpenCode tab contents

| Conductor element                                              | TerminalX behavior                                                                                                                       |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Header "OpenCode — The open source AI coding agent" + "Docs ↗" | Static header; link = `descriptor.docsUrl`.                                                                                              |
| **Providers · N configured** + "Add your first provider"       | Opens the **Providers picker modal** (§5.2). N = providers present in OpenCode's config.                                                 |
| **Models · N selected** + "Add your first OpenCode model"      | Opens a model picker scoped to configured providers. N = models enabled in OpenCode config.                                              |
| **Advanced** (collapsible)                                     | Holds the install/version block + executable override.                                                                                   |
| Green **"Installed 1.17.7"** pill                              | `probeHarness("opencode").version`; red "Not installed" if absent.                                                                       |
| **"Open in Finder ↗"**                                         | Reveals the resolved `binPath` (server-side `open -R` / xdg equivalent, gated by platform).                                              |
| **"Docs ↗"**                                                   | `descriptor.docsUrl`.                                                                                                                    |
| **"Refresh"**                                                  | Re-runs `probeHarness("opencode")` + re-reads OpenCode config counts.                                                                    |
| **"OpenCode executable path"** field                           | Override for the resolved binary. Default = bundled/`PATH`; placeholder `/usr/local/bin/opencode`; helper text verbatim from screenshot. |

### 5.2 Providers picker modal

Mirrors the "Providers" modal: a search box, brand-iconed rows, and a "View all providers (96)" footer. The canonical curated rows are:

```typescript
// src/lib/harnesses/opencode-providers.ts
export interface OpenCodeProviderEntry {
  id: string;
  label: string;
  icon: string; // brand icon key
}

export const FEATURED_OPENCODE_PROVIDERS: OpenCodeProviderEntry[] = [
  { id: "opencode-zen", label: "OpenCode Go / OpenCode Zen", icon: "opencode" },
  { id: "openai", label: "OpenAI", icon: "openai" },
  { id: "github-copilot", label: "GitHub Copilot / GitHub Models", icon: "github" },
  { id: "anthropic", label: "Anthropic", icon: "anthropic" },
  { id: "google", label: "Google", icon: "google" },
  { id: "vercel", label: "Vercel AI Gateway", icon: "vercel" },
  { id: "openrouter", label: "OpenRouter", icon: "openrouter" },
];

/** Total upstream provider count shown in the footer. */
export const TOTAL_OPENCODE_PROVIDERS = 96;
```

Selecting a provider does **not** make TerminalX speak that provider's API. It writes the provider stanza into OpenCode's own config file (OpenCode then handles the model traffic when the `opencode` CLI runs in the tmux session). TerminalX's job is config management + launch, never proxying tokens. The full 96-entry list is fetched lazily (search/"View all") rather than hard-coded; only the seven featured rows are static.

### 5.3 Executable path override

`TERMINALX_OPENCODE_BIN` env var (or the repo `.terminalx/settings.toml` `[harness.opencode] bin = "…"`) overrides PATH resolution, matching the screenshot's "Override the bundled OpenCode executable" field. Empty ⇒ use the bundled/PATH binary. The override feeds `HarnessCommandSpec.bin` resolution in `commandForHarness`.

---

## 6. Settings UI

### 6.1 Where it lives

Conductor splits settings into **User** and **Repo** scope with a left nav whose entries include **Harnesses**. TerminalX's `SettingsView.tsx` is currently a single flat scroll of `Section` blocks (server / you / terminal engine / mobile / telegram / help), rendered read-only-ish with the local `Section` + `Row` helpers and the dark palette (`#0f1117` / `#1a1d24` / `#e6f0e4` / `#00ff88`). We add a **"harnesses"** section consistent with those helpers rather than inventing a new shell.

A scope toggle (User / Repo) is added at the top of the harnesses section; Repo scope shows an **"Edit settings.toml"** affordance (Conductor analog: the repo "Edit settings.toml" button) pointing at `.terminalx/settings.toml`.

### 6.2 Component tree

```
SettingsView
└─ Section "harnesses"  (desc: "AI runtimes available to new sessions")
   ├─ ScopeTabs (User | Repo)              // new: src/components/settings/ScopeTabs.tsx
   ├─ HarnessTabs                          // new: src/components/settings/HarnessTabs.tsx
   │    tabs from listHarnesses(): Claude Code · Codex · Cursor · OpenCode[NEW]
   ├─ HarnessTabPanel (selected harness)
   │    ├─ AuthChoice (CLI ✓ | API key)    // for auth:"cli" harnesses
   │    ├─ StatusPill ("Connected" / "Not installed")
   │    ├─ AccountTable (Provider/Plan/Org/Account)   // dashes when unknown
   │    └─ RunLoginButton ("Run claude /login")
   └─ OpenCodePanel (when harness.hostsProviders)      // new: src/components/settings/OpenCodePanel.tsx
        ├─ Header + Docs↗
        ├─ ProvidersRow ("N configured" + Add your first provider → ProvidersPickerModal)
        ├─ ModelsRow ("N selected" + Add your first OpenCode model)
        └─ Advanced (collapsible)
             ├─ InstalledPill (version) · Open in Finder↗ · Docs↗ · Refresh
             └─ ExecutablePathField (placeholder /usr/local/bin/opencode)
```

All new components reuse `SettingsView`'s existing `Section`/`Row` look (same border/background tokens) and the existing pill styling pattern (see the `auth mode`/`role` pills in `SettingsView.tsx`).

### 6.3 Repo config: `.terminalx/settings.toml`

Conductor commits repo config to `.conductor/settings.toml`. TerminalX's analog is a committed `.terminalx/settings.toml` at the repo root (sibling to the existing `.terminalx-worktrees/` convention). Example:

```toml
# .terminalx/settings.toml  (Conductor analog: .conductor/settings.toml)
[harness.claude]
auth = "cli"            # or "api-key"

[harness.opencode]
bin = ""                # empty => bundled/PATH (matches "Leave empty…" helper)
providers = ["anthropic", "openrouter"]
models = ["claude-sonnet"]

[defaults]
harness = "claude"      # default harness for new sessions in this repo
```

User-scope equivalents live under `~/.terminalx/settings.toml`. Repo settings override user settings; both are optional and degrade to the built-in defaults (matching Conductor's "handle missing gracefully" behavior). This stays consistent with TerminalX's env-first model — env vars (`TERMINALX_OPENCODE_BIN`, etc.) override TOML, which overrides built-ins.

---

## 7. Dashboard (new session)

`DashboardView.tsx` currently hard-codes the kind toggle:

```typescript
// today, in DashboardView.tsx
{(
  [
    { value: "bash",   label: "bash",   color: "#00cc6e" },
    { value: "claude", label: "claude", color: "#d58fff" },
    { value: "codex",  label: "codex",  color: "#5ccfe6" },
  ] as const
).map((k) => ( /* toggle button */ ))}
```

This becomes a `listHarnesses()`-driven render, so adding "Cursor"/"OpenCode" requires no dashboard edit:

```typescript
import { listHarnesses } from "@/lib/harnesses/registry";

{listHarnesses().map((h) => (
  <button
    key={h.id}
    onClick={() => setKind(h.id)}
    style={{ background: kind === h.id ? h.color : "transparent" }}
    className={/* unchanged toggle classes */}
  >
    {h.label}
    {h.badge === "NEW" && <span className="...badge">NEW</span>}
  </button>
))}
```

- `KindIcon` (lines 36–38) gains entries for `cursor`/`opencode` (keeping the existing `claude`→`Sparkles`, `codex`→`Bot` mappings).
- The claude-only `--dangerously-skip-permissions` checkbox (`kind === "claude"`, line 606) stays gated on the harness exposing a `dangerouslySkipPermissions` option flag (data-driven check instead of a literal).
- `createSession(n, kind, …)` is unchanged structurally; `kind` is now any registry id. The `dangerouslySkipPermissions` arg still only applies where the harness declares the flag.

---

## 8. API

### 8.1 `POST /api/sessions` (modified)

In `src/app/api/sessions/route.ts`:

- `const sessionKind = kind === undefined ? "bash" : kind;`
- Replace `if (!isValidKind(sessionKind))` validation message text from _"expected bash, claude, or codex"_ to a dynamic list from `listHarnesses()`.
- `commandForKind(sessionKind, { dangerouslySkipPermissions })` already routes through the shim (§3.5), so no further change in the create path. `saveMeta({ ..., kind: sessionKind })` persists the harness id unchanged.

Everything else (worktree creation, scoping, Telegram binding, audit log line `${finalName} (${sessionKind})`) is untouched.

### 8.2 `GET /api/harnesses` (new)

`src/app/api/harnesses/route.ts`:

```typescript
export async function GET() {
  const harnesses = listHarnesses().map((h) => ({
    id: h.id,
    label: h.label,
    badge: h.badge,
    color: h.color,
    auth: h.auth,
    hostsProviders: Boolean(h.hostsProviders),
    docsUrl: h.docsUrl,
    status: probeHarness(h.id), // installed/version/connected/account/loginCommand
  }));
  return NextResponse.json({ harnesses });
}
```

Mirrors the existing route conventions in `src/app/api/sessions/route.ts` (NextResponse, try/catch → 500). Read-only; honors no scoping beyond what `SettingsView` already does. Cached briefly server-side so the version/probe shellouts don't run on every poll.

### 8.3 `POST /api/harnesses/[id]/login` (new)

Triggers the "Run \<cli\> /login" affordance by creating a managed tmux session that runs the harness's `loginCommand` in the user's scope (reusing `createSession` + `commandForHarness`-style wrapping). Returns the session name so the UI can focus it. Gated by `TERMINUS_READ_ONLY` exactly like `POST /api/sessions`.

### 8.4 `GET /api/harnesses/opencode/providers` (new)

Returns `FEATURED_OPENCODE_PROVIDERS` + `TOTAL_OPENCODE_PROVIDERS` (and, on `?all=1`/search, the lazily-fetched full 96-entry list) for the picker modal. `POST` writes the selected provider stanza into OpenCode's config; it never accepts or stores a raw API key in TerminalX state.

---

## 9. Acceptance criteria

- [ ] `SessionKind` is no longer a hard-coded 3-member union; it is the open id set sourced from the registry, and `useSessions.ts` no longer redeclares the union.
- [ ] `commandForKind`/`isValidKind` still exist (as shim re-exports) so no existing import breaks; the shell wrapper output for `bash`/`claude`/`codex` is byte-identical to today (verified by snapshot test).
- [ ] Adding a harness requires editing **only** `registry.ts` (and, if it hosts providers, the OpenCode files) — no edits to the dashboard, the API validator, or `useSessions`.
- [ ] Harnesses settings section renders one tab per registry harness, with the **OpenCode** tab carrying a **NEW** badge.
- [ ] Claude Code tab shows a CLI/API-key choice with a ✓ on the active method, a Connected/Not-installed pill, the Provider/Plan/Org/Account table (dashes when unknown — never fabricated), and a "Run claude /login" button that opens a visible tmux session.
- [ ] OpenCode tab shows Providers ("N configured" → picker modal), Models ("N selected"), and an Advanced block with an install/version pill, Open-in-Finder, Docs, Refresh, and the executable-path override (placeholder `/usr/local/bin/opencode`, verbatim helper text).
- [ ] Providers picker modal lists the 7 featured rows by their exact Conductor labels and a "View all providers (96)" footer; it does **not** list invented providers as canonical.
- [ ] Repo-scope harness settings expose an "Edit settings.toml" affordance bound to `.terminalx/settings.toml`; missing/invalid TOML degrades to built-in defaults.
- [ ] No new plaintext/"encrypted" credential store is introduced; auth stays delegated to the CLIs + `.env`.

---

## 10. Edge cases

- **Harness binary missing**: `probeHarness` reports `installed:false`; settings shows "Not installed"; the dashboard still lets the user pick it (the existing `commandForKind` fallback drops to bash with the exit-code message, so the session stays alive — preserved behavior).
- **`claude` logged out**: `connected:false`; "Run claude /login" surfaced; creating a session still works and the CLI itself prompts for login inside tmux.
- **OpenCode not installed**: red pill in Advanced; Providers/Models rows still render but with a "install OpenCode first" hint; executable-path override lets the user point at a non-standard install.
- **Legacy `SessionMeta.kind` values**: `"bash"/"claude"/"codex"` remain valid registry ids; no migration of `ai-sessions.json` needed.
- **`useSessions` type drift**: solved by both server and client importing the shared id list/type; the duplicate union in `useSessions.ts` is removed.
- **Probe cost**: version/`command -v` shellouts are cached (short TTL) and time-boxed (2s) so the settings poll and `GET /api/harnesses` stay cheap.
- **Read-only mode**: `POST /api/harnesses/[id]/login` and provider writes respect `TERMINUS_READ_ONLY` like the rest of the API.

---

## 11. File-change summary

**New**

- `src/lib/harnesses/types.ts` — descriptors, `CommandOptions`.
- `src/lib/harnesses/registry.ts` — `HARNESSES`, `listHarnesses`, `getHarness`, `isValidHarnessId`.
- `src/lib/harnesses/command.ts` — `commandForHarness`.
- `src/lib/harnesses/status.ts` — `probeHarness`, `HarnessStatus`.
- `src/lib/harnesses/opencode-providers.ts` — featured list + total.
- `src/app/api/harnesses/route.ts`, `.../[id]/login/route.ts`, `.../opencode/providers/route.ts`.
- `src/components/settings/ScopeTabs.tsx`, `HarnessTabs.tsx`, `OpenCodePanel.tsx`, `ProvidersPickerModal.tsx`.

**Modified**

- `src/lib/ai-sessions.ts` — open `SessionKind`; re-export shims for `commandForKind`/`isValidKind`/`CommandOptions`.
- `src/hooks/useSessions.ts` — import shared id/type instead of redeclaring the union.
- `src/app/api/sessions/route.ts` — dynamic validation message; otherwise unchanged.
- `src/components/dashboard/DashboardView.tsx` — registry-driven kind toggle + `KindIcon` entries; data-driven skip-permissions gate.
- `src/components/settings/SettingsView.tsx` — add the "harnesses" `Section` and scope toggle.

---

## 12. Phasing

1. **Registry refactor (no UI change):** types + registry + command + shim; snapshot-test command parity; switch the API validator and dashboard toggle to read the registry. Ships `cursor` + `opencode` as selectable ids.
2. **Harnesses settings surface:** `GET /api/harnesses` + the Harnesses section (tabs, status pill, account table, Run-login).
3. **OpenCode panel + provider picker:** install/version detection, executable override, providers modal (featured 7 + 96 total), model row.
4. **Repo/User scope + `.terminalx/settings.toml`:** scope tabs, TOML load/merge precedence (env > repo TOML > user TOML > built-ins), "Edit settings.toml".
