# Extended AI Providers for TerminalX

**Status:** Design Specification
**Date:** 2026-06-25
**Author:** TerminalX Team
**Version:** 3.0
**Backs:** GitHub issue #8 (extended-providers)
**Builds on:** `docs/conductor-parity/designs/custom-providers/01-spec.md` (the data-driven
**harness registry** — `HarnessDescriptor`, `listHarnesses`/`getHarness`/`isValidHarnessId`,
and `commandForHarness` in `src/lib/harnesses/`). This spec does NOT redefine that registry; it
adds the **OpenCode Providers picker UI**, the **per-provider OpenCode config** it writes, and
the **dashboard/session wiring** for harness selection on top of it.

> **Safety correction (2026-07-23):** LocalTmux no longer accepts or emits a
> permission-bypass option, and Codex no longer starts with `--yolo`. Older
> request/command examples below are retained as design history and superseded
> by `custom-providers/00-corrections.md`.

> **Note (v3.0):** Earlier drafts of this spec assumed an `AIProvider` interface, a
> `providerRegistry`, a `data/provider-credentials/credentials.json` vault, and a "CLI-wrap vs
> HTTP" execution model in which TerminalX ran a `terminalx-chat` client that spoke HTTP to
> OpenAI/Anthropic/Google/etc. **All of those were removed.** The canonical
> `custom-providers/01-spec.md` (and its `00-corrections.md`) explicitly reject them: there is
> no `AIProvider` interface (it is a `HarnessDescriptor` table), no credential vault (auth is
> delegated to the CLIs + `.env`), and TerminalX never proxies a provider's API
> (`01-spec.md` §5.2: _"TerminalX's job is config management + launch, never proxying tokens"_).
> The seven featured providers + the 96-entry tail are **OpenCode's own providers**, configured
> into OpenCode's config and driven by the `opencode` CLI — not runtimes TerminalX invokes over
> HTTP. This spec is rebased onto that reality.

---

## Executive Summary

TerminalX today supports three session kinds — `bash`, `claude`, `codex` — each mapping to an
optional CLI binary (`src/lib/ai-sessions.ts`). The prior draft of this spec invented a
provider list (ChatGPT / Gemini / Ollama) that does **not** match the Conductor product we are
mirroring. This rewrite replaces that guesswork with Conductor's **real** provider experience:
the **OpenCode harness** hosts a searchable **"Providers"** modal listing OpenCode Go /
OpenCode Zen, OpenAI, GitHub Copilot / GitHub Models, Anthropic, Google, Vercel AI Gateway, and
OpenRouter, with a **"View all providers (96)"** footer.

The deliverable is the TerminalX analog of that modal plus the per-provider configuration it
opens into. Crucially, these providers are **OpenCode's** providers: selecting one writes a
provider stanza into OpenCode's own config file, and the `opencode` CLI (the only harness
TerminalX actually launches here) handles the model traffic when it runs in the tmux session.
TerminalX does **not** speak any provider's API directly — there is no HTTP proxy and no
`terminalx-chat` client. The execution backbone reuses the **harness registry** from
`custom-providers/01-spec.md` (`HarnessDescriptor` + `commandForHarness`), where the only new
launchable harnesses are real CLIs (`cursor`, `opencode`). All artifacts use TerminalX naming
(`TERMINALX_*`, `.terminalx/`), noting the Conductor analog being mirrored.

---

## Conductor UI reference (from screenshots)

These are the authoritative UI facts this feature depends on. Where TerminalX diverges, it is
called out explicitly.

### Harnesses settings page (where providers are reached)

- Title **"Harnesses"**. One sub-tab per harness: **"Claude Code"**, **"Codex"**, **"Cursor"**,
  **"OpenCode"** (OpenCode carries a **"NEW"** badge).
- **OpenCode** tab contents:
  - Header row: **"OpenCode — The open source AI coding agent"** + **"Docs ↗"** link.
  - **"Providers 0 configured"** with an **"Add your first provider"** button.
  - **"Models 0 selected"** with an **"Add your first OpenCode model"** button.
  - Collapsible **"Advanced"**: green **"Installed 1.17.7"** pill, **"Open in Finder ↗"**,
    **"Docs ↗"**, **"Refresh"**.
  - **"OpenCode executable path"** field, placeholder `/usr/local/bin/opencode`, helper text:
    _"Override the bundled OpenCode executable with a custom one. Leave empty to use the
    bundled version (recommended)."_
- **Claude Code** tab (for contrast — it is harness-native auth, not the gateway picker):
  - **"Authentication"** section: two large choices **"CLI"** (terminal icon, ✓ when active)
    vs **"API key"** (key icon).
  - green **"Connected"** pill; a table Provider=`Anthropic API`, Plan=`Max`, Org, Account;
    a **"Run claude /login"** button (play icon).

### Provider picker modal (opened from OpenCode "Add your first provider")

- Modal titled **"Providers"** with a **"Search providers"** input.
- Provider rows, each with a brand icon and expandable. The canonical visible list is:
  1. **OpenCode Go / OpenCode Zen**
  2. **OpenAI**
  3. **GitHub Copilot / GitHub Models**
  4. **Anthropic**
  5. **Google**
  6. **Vercel AI Gateway**
  7. **OpenRouter**
- Footer: **"View all providers (96)"**. The total catalog is **96** providers.
- **IMPORTANT:** Do **not** invent `ChatGPT` / `Gemini` / `Ollama` as the canonical entries.
  The brand-correct names are the seven above plus the 96-entry catalog.

### Models settings page (where the per-session/default model is chosen)

- **"Default model"** = model dropdown (e.g. `Opus 4.8 1M`) + **"Effort"** dropdown (e.g.
  `Effort high`); sublabel _"Model for new chats"_.
- **"Review model"** = its own model + Effort dropdowns; sublabel _"Model for code reviews"_.
  Code review uses a **separate, independently-configurable** model from authoring.

### Repo vs User scope

- Settings have two top-level scope tabs: **"User"** and **"Repo"**.
- Repo-scoped harness screens show a top-right **"Edit settings.toml"** button — Conductor
  commits repo config to `.conductor/settings.toml`.
- **TerminalX analog:** committed repo config at **`.terminalx/settings.toml`** with an
  **"Edit settings.toml"** affordance; provider _credentials_ never go in the committed file
  (see §6).

---

## 1. Scope and Non-Goals

### 1.1 In scope (this spec, issue #8)

- The **OpenCode Providers picker modal** (TerminalX analog of Conductor's searchable
  "Providers", reached from the OpenCode harness tab).
- Per-provider **OpenCode config**: which provider stanza + (where relevant) model is written
  into OpenCode's own config. TerminalX manages this config; it does not proxy the provider.
- The seven canonical featured providers + a lazily-fetched 96-entry tail, sourced from
  `src/lib/harnesses/opencode-providers.ts` (per `custom-providers/01-spec.md` §5.2).
- **Dashboard + session wiring** so the registry-driven harness set (`cursor`, `opencode`)
  is selectable and persisted via the existing `SessionKind`/`commandForHarness` path.

### 1.2 Out of scope (owned by sibling specs — do not duplicate)

- The harness registry itself — `HarnessDescriptor`, `listHarnesses`/`getHarness`/
  `isValidHarnessId`, `commandForHarness`, `probeHarness`, the Harnesses settings shell, and
  the `.terminalx/settings.toml` repo config — all owned by **`custom-providers/01-spec.md`**.
  This spec consumes them; it does **not** introduce an `AIProvider` interface, a
  `providerRegistry`, or a credential vault (the canonical spec removed all three).
- Code-review model selection surface — owned by the **pr-review** spec set
  (`docs/conductor-parity/designs/pr-review/`). We only note that review uses a separate model.
- The **Models settings page** (Default model / Review model rows and their **Effort**
  dropdowns) — owned by **`model-settings.spec.md`**. Effort is a Models-page concern, not an
  OpenCode-provider-picker concern (the picker modal has only search + brand rows + the
  "View all providers (96)" footer; no per-provider Effort control).
- Per-workspace injected port (Conductor's `CONDUCTOR_PORT` → TerminalX `TERMINALX_PORT`) and
  setup/run scripts — owned by **`workspace-config.spec.md`**.

### 1.3 Naming

- TerminalX harness ids stay lowercase (`opencode`, `cursor`, …) to match the existing
  `SessionKind` string convention in `src/lib/ai-sessions.ts`. OpenCode **provider** ids
  (`anthropic`, `openrouter`, …) are OpenCode-config identifiers, not TerminalX session kinds.
- Committed repo config: **`.terminalx/settings.toml`** (Conductor analog:
  `.conductor/settings.toml`) — defined by `custom-providers/01-spec.md` §6.3; this spec only
  reads/writes the OpenCode `[harness.opencode] providers`/`models` keys it already declares.
- Executable override env: **`TERMINALX_OPENCODE_BIN`** (per `custom-providers/01-spec.md`
  §5.3), consistent with the existing `TERMINALX_WORKTREES_ROOT` in `src/lib/git-worktree.ts`.
  Runtime tunables otherwise remain `TERMINUS_*` (see AGENTS.md).

---

## 2. Verified Current State (codebase)

All references below were read from the repo at spec time.

| Symbol                                          | File                                             | Current shape                                                                                                                                        |
| ----------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SessionKind`                                   | `src/lib/ai-sessions.ts:6`                       | `"bash" \| "claude" \| "codex"`                                                                                                                      |
| `SessionKind` (duplicate)                       | `src/hooks/useSessions.ts:5`                     | independently declares `"bash" \| "claude" \| "codex"`; used at lines 21/45/76                                                                       |
| `SessionMeta`                                   | `src/lib/ai-sessions.ts:10`                      | `{ name, kind, createdAt, createdBy?, managed?, cwd?, worktree? }`                                                                                   |
| `CLI_BINS`                                      | `src/lib/ai-sessions.ts:110`                     | `{ bash: null, claude: "claude", codex: "codex" }`                                                                                                   |
| `commandForKind`                                | `src/lib/ai-sessions.ts:128`                     | wraps `bash -lc '<bin>; ec=$?; … exec bash -l'`; codex/claude auth is **CLI-delegated** (no env-key export)                                          |
| `isValidKind`                                   | `src/lib/ai-sessions.ts:139`                     | guard for the three literals                                                                                                                         |
| `saveMeta`/`getMeta`/`listMetadata`             | `src/lib/ai-sessions.ts`                         | persist `data/ai-sessions.json` (mode `0600`)                                                                                                        |
| `POST /api/sessions`                            | `src/app/api/sessions/route.ts:96`               | reads `{name, kind, dangerouslySkipPermissions, cwd, worktree}`, validates with `isValidKind`, calls `commandForKind`, `createGitWorktreeForSession` |
| `KindIcon` + kind pills                         | `src/components/dashboard/DashboardView.tsx:36`  | bash `#00cc6e`, claude `#d58fff`, codex `#5ccfe6`; toggle hard-coded at line 455                                                                     |
| `SettingsView` `Section`/`Row`                  | `src/components/settings/SettingsView.tsx:38,58` | dark-theme settings primitives                                                                                                                       |
| `worktreesBaseDir` / `TERMINALX_WORKTREES_ROOT` | `src/lib/git-worktree.ts:54`                     | precedent for `TERMINALX_*` env naming                                                                                                               |
| `ensureSecureDir`                               | `src/lib/secure-dir.ts:7`                        | used to create `0700` dirs (e.g. `data/`)                                                                                                            |

> There is **no** `src/lib/providers/` or `src/app/api/providers/` (verified — grep returns
> zero hits), and no `AIProvider`/`providerRegistry`/`getEnvSetupCommands`/`OPENAI_API_KEY` in
> `src/`. The harness registry this spec builds on lives at **`src/lib/harnesses/`** with routes
> under **`/api/harnesses`**, both introduced by `custom-providers/01-spec.md` (which this spec
> assumes lands first). All new code in this spec lands under those same paths.

---

## 3. OpenCode Provider Data Model (this spec's additions)

The harness registry (`HarnessDescriptor`, `listHarnesses`, `commandForHarness`) comes from
`custom-providers/01-spec.md` §3 and is **not** redefined here. `custom-providers/01-spec.md`
§5.2 also already declares the curated OpenCode provider list (`OpenCodeProviderEntry`,
`FEATURED_OPENCODE_PROVIDERS`, `TOTAL_OPENCODE_PROVIDERS = 96`) in
`src/lib/harnesses/opencode-providers.ts`. This spec **extends that file** with the per-row
detail the picker needs and the **configured-instance** record OpenCode persists. Two layers:

1. **Provider catalog entry** (`OpenCodeProviderEntry`, extended) — static, describes an
   OpenCode provider that _can_ be added (the rows in the modal). 7 featured + a lazily-fetched
   96-entry tail. These are **OpenCode's** providers; TerminalX never speaks their API.
2. **Configured OpenCode provider** (`ConfiguredOpenCodeProvider`) — a provider the user added,
   recorded so OpenCode's config can be (re)written. There is **no** TerminalX credential store:
   any secret the provider needs is supplied to OpenCode through OpenCode's own config / the
   environment (`.env`), per `custom-providers/01-spec.md` §4.2.

> **There is no `invocation` / `cli-wrap` / `http` distinction.** Every featured provider is an
> OpenCode config stanza; the **only** harness TerminalX launches for all of them is the
> `opencode` CLI (via `commandForHarness("opencode")`). `custom-providers/01-spec.md` §5.2 is
> explicit: _"Selecting a provider does not make TerminalX speak that provider's API… It writes
> the provider stanza into OpenCode's own config file."_ There is no `terminalx-chat` client and
> no HTTP proxy in this design.

### 3.1 `OpenCodeProviderEntry` (extended)

`custom-providers/01-spec.md` §5.2 defines the base `{ id, label, icon }`. This spec adds the
optional fields the picker UI binds to. The base shape and the 7 featured ids/labels are
**unchanged** — they are authoritative.

```typescript
// src/lib/harnesses/opencode-providers.ts (extended; base type from 01-spec.md §5.2)

export interface OpenCodeProviderEntry {
  /** OpenCode-config provider id (NOT a TerminalX SessionKind). */
  id: string;
  /** Brand-correct display name as shown in the picker. */
  label: string;
  /** Brand icon key resolved by the UI. */
  icon: string;
  /**
   * Some rows present two brands together; the search matches each so the UI
   * mirrors what the user sees in Conductor.
   * e.g. ["OpenCode Go", "OpenCode Zen"], ["GitHub Copilot", "GitHub Models"].
   * Defaults to [label] when omitted.
   */
  brands?: string[];
  /** True for the 7 curated featured rows; the 96-entry tail is featured:false. */
  featured?: boolean;
  /**
   * Whether OpenCode needs the user to supply an endpoint URL for this provider
   * (gateways like Vercel AI Gateway / OpenRouter). Informational for the picker;
   * the value is written into OpenCode's config, not consumed by TerminalX.
   */
  endpointEditable?: boolean;
  /** Docs link shown as "Docs ↗" next to the row. */
  docsUrl?: string;
}
```

> **No `invocation`, `authKind`, `defaultEndpoint`, `cliBin`, or `effortLevels` field.** Auth is
> handled inside OpenCode's own config (no TerminalX `authKind` enum); the launchable binary is
> always `opencode` (`HarnessDescriptor.command.bin`, not a per-provider `cliBin`); and **Effort
> is a Models-settings concept** (`model-settings.spec.md` / the Models page Default-model and
> Review-model rows), not a provider-picker field — see §1.2 and §7.

### 3.2 The featured catalog (the seven real rows)

These seven entries are authoritative — they are the visible rows in Conductor's modal, and
they match `FEATURED_OPENCODE_PROVIDERS` in `custom-providers/01-spec.md` §5.2 exactly. Do
**not** substitute `ChatGPT`/`Gemini`/`Ollama` names.

```typescript
// src/lib/harnesses/opencode-providers.ts (continued)

export const FEATURED_OPENCODE_PROVIDERS: OpenCodeProviderEntry[] = [
  {
    id: "opencode-zen",
    label: "OpenCode Go / OpenCode Zen",
    brands: ["OpenCode Go", "OpenCode Zen"],
    icon: "opencode",
    featured: true,
    docsUrl: "https://opencode.ai/docs",
  },
  { id: "openai", label: "OpenAI", brands: ["OpenAI"], icon: "openai", featured: true },
  {
    id: "github-copilot",
    label: "GitHub Copilot / GitHub Models",
    brands: ["GitHub Copilot", "GitHub Models"],
    icon: "github",
    featured: true,
  },
  { id: "anthropic", label: "Anthropic", brands: ["Anthropic"], icon: "anthropic", featured: true },
  { id: "google", label: "Google", brands: ["Google"], icon: "google", featured: true },
  {
    id: "vercel",
    label: "Vercel AI Gateway",
    brands: ["Vercel AI Gateway"],
    icon: "vercel",
    featured: true,
    endpointEditable: true, // gateway: OpenCode config takes a custom base URL
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    brands: ["OpenRouter"],
    icon: "openrouter",
    featured: true,
    endpointEditable: true,
  },
];

/** Total upstream provider count shown in the footer (from 01-spec.md §5.2). */
export const TOTAL_OPENCODE_PROVIDERS = 96;
```

### 3.3 The "View all providers (96)" tail

- Only the 7 featured rows are static. The full 96-entry list is **fetched lazily** (search /
  "View all providers") rather than hard-coded, exactly as `custom-providers/01-spec.md` §5.2
  states; there is no bundled 96-entry JSON and no catalog-override env var.
- The modal shows the 7 featured rows; **"View all providers (96)"** loads the full list, where
  `96 = TOTAL_OPENCODE_PROVIDERS`, filtered live by the **"Search providers"** input (matches
  `label` + each of `brands`).
- The list source is OpenCode itself (resolved server-side via the `opencode` CLI / its provider
  index), surfaced through `GET /api/harnesses/opencode/providers` (§8). TerminalX does not
  maintain its own competing catalog.

```typescript
// served by GET /api/harnesses/opencode/providers (see §8)
export function featuredProviders(): OpenCodeProviderEntry[] {
  return FEATURED_OPENCODE_PROVIDERS;
}
export function providerCount(): number {
  return TOTAL_OPENCODE_PROVIDERS; // 96
}
```

### 3.4 `ConfiguredOpenCodeProvider` (a saved instance)

What TerminalX records when a provider is added, so OpenCode's config can be (re)written and the
"Providers · N configured" count rendered. It carries **no secret and no TerminalX credential
ref** — secrets live in OpenCode's config / `.env`, per `custom-providers/01-spec.md` §4.2.

```typescript
// src/lib/harnesses/opencode-providers.ts (continued)

export interface ConfiguredOpenCodeProvider {
  /** OpenCode provider id this instance is based on (e.g. "anthropic"). */
  providerId: string;
  /** Optional endpoint for endpointEditable gateways (written into OpenCode config). */
  endpoint?: string;
  /** Models the user enabled for this provider (drives "Models · N selected"). */
  models?: string[];
  /** "user" or "repo" — which scope persisted this instance. */
  scope: "user" | "repo";
}
```

> Model **selection** here is OpenCode's "Models · N selected" registry, not a per-session
> author/review model. Effort and the Default/Review model split are owned by the Models page
> (`model-settings.spec.md`); this record never carries an `effort` field.

---

## 4. Session Wiring (consumes the harness registry)

The session-kind plumbing — the open `SessionKind`, `commandForHarness` (replacing
`commandForKind`), and `isValidHarnessId` (replacing `isValidKind`) — is **owned by**
`custom-providers/01-spec.md` §3 (the `HarnessDescriptor` refactor of `CLI_BINS` /
`commandForKind` in `src/lib/ai-sessions.ts` → new `src/lib/harnesses/`). This spec does **not**
redefine it. There is **no** per-provider `commandForKind` path, no `invocation: "cli-wrap" |
"http"` distinction, and no `terminalx-chat` HTTP client: the only harness this spec launches is
the `opencode` CLI itself, via the registry's `commandForHarness("opencode")`.

The two changes this spec actually needs are: (a) ensure `opencode` is selectable as a harness
id (it is, per `01-spec.md` §3.3's `HARNESSES` table), and (b) keep the **client** `SessionKind`
in sync with the server's open id set (the bug in §4.1).

### 4.1 `SessionKind` stays a single shared open set (no client/server drift)

`01-spec.md` §3.5 widens `SessionKind` to the open id set in `src/lib/ai-sessions.ts`:

```typescript
// src/lib/ai-sessions.ts (per custom-providers/01-spec.md §3.5)
export type SessionKind = string; // open id set; was "bash" | "claude" | "codex"
```

**The independent redeclaration must be removed too.** `src/hooks/useSessions.ts:5` currently
declares its own copy:

```typescript
// src/hooks/useSessions.ts:5 (VERIFIED — must be removed)
export type SessionKind = "bash" | "claude" | "codex"; // used at lines 21, 45, 76
```

If only `ai-sessions.ts` is widened, the client type stays a closed 3-member union and the
dashboard's `createSession` path silently rejects any configured-provider/`opencode` kind. Per
`01-spec.md` §3.5 / §9 acceptance criteria (_"useSessions.ts no longer redeclares the union"_),
both server and client must route through **one** shared client-safe source — e.g. import the
`SessionKind` type (and the `HARNESS_IDS` value list) that `01-spec.md` exports — instead of the
duplicate union. This spec lists `src/hooks/useSessions.ts` in its modify set (§12) for exactly
this reason.

`SessionMeta` is structurally unchanged: `kind: SessionKind` now accepts the open id set, so
`opencode` sessions persist with `kind: "opencode"` and existing `bash`/`claude`/`codex` records
stay valid. `getMeta`, `saveMeta`, `listMetadata`, and the `0600` atomic write are untouched.

> **No `SessionMeta.provider` sub-record.** An OpenCode session is just `kind: "opencode"`. The
> chosen OpenCode _provider_ (Anthropic, OpenRouter, …) is recorded in **OpenCode's own config**
> (and mirrored into `.terminalx/settings.toml [harness.opencode] providers`, per `01-spec.md`
> §5.3 / §6.3), not in a TerminalX session-meta field. There is no `modelId`/`effort`/`endpoint`/
> `invocation` payload on the session — Effort lives on the Models page (§1.2), and TerminalX
> never holds a provider endpoint because it never speaks the provider's API.

### 4.2 Launch is always the `opencode` CLI (no HTTP path)

There is no provider-aware branch in the command builder. `commandForHarness("opencode")`
(`01-spec.md` §3.4) produces the **exact** existing tmux wrapper, byte-for-byte:

```bash
bash -lc 'opencode; ec=$?; echo; echo "[opencode exited with code $ec — dropping to bash]"; exec bash -l'
```

`01-spec.md` §5.2 is explicit: _"Selecting a provider does not make TerminalX speak that
provider's API… It writes the provider stanza into OpenCode's own config file (OpenCode then
handles the model traffic when the `opencode` CLI runs in the tmux session). TerminalX's job is
config management + launch, never proxying tokens."_ When `opencode` runs, it reads the provider
stanza this spec wrote and handles all model traffic itself.

> **Auth is delegated, never injected by TerminalX.** OpenCode reads its provider credentials
> from OpenCode's own config / the environment (`.env`), per `01-spec.md` §4.2. There is **no**
> `getEnvSetupCommands()` and **no** `OPENAI_API_KEY` export anywhere in the repo (grep of
> `src/` returns zero hits), and Codex/Claude auth is **CLI-delegated** (`commandForKind` just
> runs the binary). The earlier "matches the existing Codex provider, which exports
> `OPENAI_API_KEY`" claim was fabricated — there is no such precedent — and is removed.

### 4.3 Kind validation reuses `isValidHarnessId`

`POST /api/sessions` validates with `isValidHarnessId` (`01-spec.md` §3.3/§8.1), which already
accepts every registry id including `opencode`. This spec introduces **no** separate
`configuredIds`-parameterized validator — an OpenCode session's kind is just the registry id
`"opencode"`, not a per-OpenCode-provider id. (OpenCode _provider_ ids like `anthropic` are
OpenCode-config identifiers, never TerminalX session kinds — see §1.3.)

---

## 5. Provider Picker UI (the modal)

TerminalX analog of Conductor's **"Providers"** modal. It is reached from the **Harnesses →
OpenCode** settings sub-tab via **"Add your first provider"**, matching Conductor exactly.

### 5.1 Component tree

```
SettingsView                                   (existing, src/components/settings/SettingsView.tsx)
└─ <ScopeTabs>                  User | Repo     (NEW — mirrors Conductor scope tabs)
   └─ HarnessesSettings                         (NEW)
      ├─ <HarnessTabs>          Claude Code | Codex | Cursor | OpenCode[NEW]
      └─ OpenCodeHarnessPanel                    (NEW)
         ├─ header: "OpenCode — The open source AI coding agent"  + Docs ↗
         ├─ ProvidersSection    "Providers  {n} configured"
         │  └─ [Add your first provider] ──opens──▶ ProviderPickerModal
         ├─ ModelsSection       "Models  {n} selected"
         │  └─ [Add your first OpenCode model]
         └─ <AdvancedCollapsible>
            ├─ green "Installed {version}" pill
            ├─ Open in Finder ↗ | Docs ↗ | Refresh
            └─ ExecutablePathField  placeholder "/usr/local/bin/opencode"

ProviderPickerModal                             (NEW — the searchable "Providers" modal)
├─ DialogTitle "Providers"
├─ <SearchInput placeholder="Search providers" />
├─ <ProviderRow> × 7 (featured)   icon + label(brands) + expand chevron
│   └─ expanded ▶ ProviderConfigForm
├─ <ViewAllToggle>  "View all providers (96)"
└─ (when expanded) <ProviderRow> × (96) filtered by search

ProviderConfigForm                              (NEW — per-provider config, §6)
```

Reuse existing primitives: `Section`/`Row` from `SettingsView.tsx`, `Dialog` from
`@/components/ui/dialog`, and the colored-pill pattern from `DashboardView.tsx` `KindIcon`.

### 5.2 Modal behavior / acceptance criteria

- **AC-1** Modal title is exactly **"Providers"**; input placeholder exactly **"Search
  providers"**.
- **AC-2** Initial view shows exactly the 7 featured rows in the documented order, each with
  brand icon and the brand-correct label (including the two-brand labels for OpenCode and
  GitHub).
- **AC-3** Footer reads **"View all providers (96)"** where 96 = `providerCount()`
  (`TOTAL_OPENCODE_PROVIDERS`). The total comes from the lazily-fetched OpenCode provider list,
  not a TerminalX catalog-override env var (there is none).
- **AC-4** Typing in search filters by `label` and any `brands` entry, case-insensitive,
  across the **full** catalog (not just the 7), and the count in the footer updates to the
  filtered total.
- **AC-5** Selecting a row expands `ProviderConfigForm` inline (Conductor expandable rows), it
  does **not** navigate away.
- **AC-6** `ChatGPT`, `Gemini`, `Ollama` are NOT shown as canonical featured rows. (Regression
  guard against the prior draft.)

---

## 6. Per-Provider Configuration

`ProviderConfigForm` collects the few fields OpenCode needs to write a provider **stanza into
OpenCode's own config**, then mirrors the non-secret keys into `.terminalx/settings.toml`. There
is **no TerminalX credential vault**: any secret a provider needs is supplied to OpenCode through
OpenCode's own config / the environment (`.env`), per `custom-providers/01-spec.md` §4.2. The
form has **no `authKind`/`invocation` switch** — every provider is an OpenCode config stanza and
the launched harness is always the `opencode` CLI.

### 6.1 Field matrix

The only branch is whether the provider is a **gateway** (`endpointEditable`, needing a base
URL) or not. Auth is OpenCode's concern; TerminalX does not render a credential vault input that
it would then store. Where a secret is genuinely required, the form directs it to OpenCode's own
config / `.env`, never to TerminalX state.

| Provider class                                              | Fields shown                                               | Notes                                                                     |
| ----------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------- |
| Bundled (OpenCode Go/Zen)                                   | none — "Use bundled binary"; optional executable path      | Mirrors OpenCode "executable path" field; bundled by default.             |
| Standard (OpenAI, Anthropic, Google, GitHub Copilot/Models) | **Model** (enabled in OpenCode)                            | Auth handled by OpenCode (its own login / `.env`); no TerminalX-held key. |
| Gateway (Vercel AI Gateway, OpenRouter)                     | **Endpoint URL** (editable, `endpointEditable`), **Model** | Endpoint written into OpenCode's config.                                  |

> **No Effort field here.** Effort lives on the **Models** settings page (`model-settings.spec.md`
> / the Default-model & Review-model rows), not the OpenCode provider picker. Ground truth shows
> the picker modal has only search + brand rows + the "View all providers (96)" footer — no
> per-provider Effort control (see §1.2, §3.1, §7).

### 6.2 Form contract

Matches `ConfiguredOpenCodeProvider` (§3.4): no `apiKey`, no `effort`, no `credentialRef`.

```typescript
interface ProviderConfigDraft {
  providerId: string; // OpenCode provider id, e.g. "anthropic" (NOT a SessionKind)
  endpoint?: string; // only when entry.endpointEditable (gateways)
  models?: string[]; // models enabled for this provider in OpenCode
  scope: "user" | "repo"; // which scope tab is active
}
```

- **Credential handling:** TerminalX stores **no secret**. If a provider needs a key, it is
  supplied to OpenCode through OpenCode's own config / the environment (`.env`) that sessions
  already source — there is no `POST /api/providers/:id/credentials` route and no
  `data/provider-credentials/credentials.json` vault (both were removed by `01-spec.md` §4.2 /
  §9, which states verbatim: _"No new plaintext/'encrypted' credential store is introduced; auth
  stays delegated to the CLIs + .env."_).
- **Repo scope:** the provider id (and, for gateways, the endpoint; plus enabled models) is
  written to `.terminalx/settings.toml` under `[harness.opencode]` (the `providers`/`models`/`bin`
  keys `01-spec.md` §6.3 already declares); the **"Edit settings.toml"** button (top-right, repo
  scope) opens that file.
- **User scope:** the same non-secret keys persist to the user-scope
  `~/.terminalx/settings.toml` (`01-spec.md` §6.3). This spec does **not** introduce a separate
  `data/provider-prefs.json` — that file exists in no spec and no repo path (grep: zero hits).

### 6.3 `.terminalx/settings.toml` shape (repo scope)

Conductor analog: `.conductor/settings.toml`. This is the `[harness.opencode]` block defined by
`custom-providers/01-spec.md` §6.3; this spec only reads/writes its `providers`/`models` keys.

```toml
# .terminalx/settings.toml  (committed; secrets excluded — owned by 01-spec.md §6.3)
[harness.opencode]
bin       = ""                            # empty => bundled/PATH
providers = ["anthropic", "openrouter"]   # OpenCode provider ids the user added
models    = ["claude-opus-4-8"]           # models enabled in OpenCode

[defaults]
harness = "opencode"                      # default harness for new sessions in this repo
```

> Code-review model selection (Conductor's separate **"Review model"**) is **not** an OpenCode
> provider concern — it is owned by the Models page / the **pr-review** spec set
> (`docs/conductor-parity/designs/pr-review/`). It is intentionally not represented in this
> block.

### 6.4 Acceptance criteria

- **AC-7** No API-key/secret field is persisted by TerminalX; the form never writes a secret to
  `.terminalx/settings.toml` and never to any TerminalX-owned credential file (there is none).
  Provider auth is delegated to OpenCode's config / `.env`.
- **AC-8** For gateways (`endpointEditable`), the endpoint URL is editable; for all other
  providers no endpoint field is shown (TerminalX never holds a provider endpoint).
- **AC-9** The model field lists models for the selected provider; for gateways the field is
  free-form text with optional suggestions. Enabled models drive OpenCode's "Models · N
  selected" count.
- **AC-10** Saving in **Repo** scope writes the non-secret `[harness.opencode]` keys to
  `.terminalx/settings.toml` and the "Edit settings.toml" button opens that file; saving in
  **User** scope writes the same keys to `~/.terminalx/settings.toml`. No secret is written in
  either scope.
- **AC-11** After save the OpenCode panel's **"Providers {n} configured"** count increments.

---

## 7. Runtime: one harness, the `opencode` CLI (no HTTP path)

There is a **single** execution strategy. Selecting any of the seven providers does **not** make
TerminalX speak that provider's API — it writes the provider's stanza into OpenCode's own config,
and the **`opencode` CLI** runs in the PTY and handles all model traffic itself. There is no
`terminalx-chat` client, no `invocation: "cli-wrap" | "http"` distinction, and no HTTP proxy.
`custom-providers/01-spec.md` §5.2 states this verbatim: _"TerminalX's job is config management +
launch, never proxying tokens."_

### 7.1 Launch (always the OpenCode harness)

- The `opencode` binary runs inside the PTY via `commandForHarness("opencode")` (`01-spec.md`
  §3.4). Availability = binary on PATH (`probeHarness("opencode")`, the existing `command -v`
  check).
- Generated command — identical for every configured provider (the provider lives in OpenCode's
  config, not in argv):
  ```bash
  bash -lc 'opencode; ec=$?; echo; echo "[opencode exited with code $ec — dropping to bash]"; exec bash -l'
  ```
- Bundled-binary override: OpenCode's **"OpenCode executable path"** field (placeholder
  `/usr/local/bin/opencode`) maps to `TERMINALX_OPENCODE_BIN` / the `[harness.opencode] bin` key
  (`01-spec.md` §5.3), feeding `HarnessCommandSpec.bin` resolution. Empty → bundled binary
  (recommended), per Conductor's helper text.

### 7.2 Provider configuration is OpenCode's, not a TerminalX runtime

- OpenAI, Anthropic, Google, GitHub Copilot/Models, Vercel AI Gateway, OpenRouter are all
  **OpenCode providers**. Adding one writes a stanza into OpenCode's config; OpenCode then routes
  model traffic when its CLI runs. TerminalX never imports a credential or endpoint into its own
  process and never makes a provider API call.
- For **gateways** (`endpointEditable`), the endpoint the user enters is written into OpenCode's
  config so OpenCode can target a self-hosted gateway. TerminalX neither resolves nor pings that
  endpoint.

### 7.3 Availability check

Reuses `probeHarness("opencode")` from `custom-providers/01-spec.md` §4.1:

- `command -v opencode` (2s timeout); missing → the OpenCode tab's Advanced block shows
  red "Not installed" instead of the green "Installed {version}" pill, with `docsUrl`.
- Provider-level credential validity is **OpenCode's** responsibility (its own login / config) —
  TerminalX does not hold or verify provider secrets.

---

## 8. API Surface

Reuses the **harness** route family from `custom-providers/01-spec.md` §8 — there is **no**
`/api/providers/*` route family (no `src/app/api/providers/` exists; grep returns zero hits, and
`01-spec.md` rejects it). The OpenCode provider picker is served by the existing
`GET /api/harnesses/opencode/providers` route (`01-spec.md` §8.4). This spec adds **no new top-
level route**; it only extends the OpenCode providers route's read shape and `POST` write.

| Method & path                                          | Purpose                                                                                                        | Source                                               |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `GET /api/harnesses`                                   | Harness list + status (incl. `opencode`)                                                                       | custom-providers §8.2                                |
| `GET /api/harnesses/opencode/providers`                | Featured 7 + total 96 for the picker                                                                           | custom-providers §8.4 (read shape **extended** here) |
| `GET /api/harnesses/opencode/providers?all=1&q=<term>` | Full 96, filtered by search                                                                                    | custom-providers §8.4 (extended)                     |
| `POST /api/harnesses/opencode/providers`               | Write the selected provider stanza into OpenCode config + mirror non-secret keys to `.terminalx/settings.toml` | custom-providers §8.4                                |
| `POST /api/harnesses/[id]/login`                       | "Run \<cli\> /login" affordance                                                                                | custom-providers §8.3                                |
| `POST /api/sessions`                                   | Accepts `kind: "opencode"` (no new body field)                                                                 | existing route, unchanged here                       |

There is **no** `GET /api/providers/catalog`, no `GET /api/providers`, no
`POST /api/providers/config`, and no `POST|DELETE /api/providers/:id/credentials`. The
credential routes were removed by `01-spec.md` §4.2 (auth = CLI + `.env`); the catalog/config
routes are folded into `/api/harnesses/opencode/providers`.

### 8.1 `GET /api/harnesses/opencode/providers`

Extends the read shape `01-spec.md` §8.4 returns (the base `{ id, label, icon }` rows + total)
with this spec's optional picker fields (§3.1). No `invocation`/`authKind` keys — they do not
exist in this model.

```jsonc
// 200
{
  "count": 96,
  "featured": [
    {
      "id": "opencode-zen",
      "label": "OpenCode Go / OpenCode Zen",
      "brands": ["OpenCode Go", "OpenCode Zen"],
      "icon": "opencode",
      "featured": true,
    },
    { "id": "openai", "label": "OpenAI", "brands": ["OpenAI"], "icon": "openai", "featured": true },
    // … 5 more, in documented order
  ],
}
```

`POST` (write the selected provider) carries only the non-secret `ConfiguredOpenCodeProvider`
shape (§3.4): `{ providerId, endpoint?, models?, scope }`. It never accepts or stores a raw API
key in TerminalX state (`01-spec.md` §8.4).

### 8.2 `POST /api/sessions` (unchanged by this spec)

Creating an OpenCode session is just `kind: "opencode"` — no new body field:

```jsonc
{
  "name": "opencode-chat",
  "kind": "opencode",
  "cwd": ".",
  "worktree": { "create": false },
}
```

- Validation: `isValidHarnessId(kind)` (`01-spec.md` §3.3/§8.1) already accepts `"opencode"`.
  Unknown id → `400`. There is no `configuredIds` parameter and no `provider` payload.
- The route calls `commandForHarness("opencode", { dangerouslySkipPermissions })` — unchanged
  from `01-spec.md` §8.1 — and persists `kind: "opencode"` into `SessionMeta`. The audit line
  stays `${finalName} (${sessionKind})` (`01-spec.md` §8.1); the chosen OpenCode provider lives
  in OpenCode's config, not the audit detail.

---

## 9. Dashboard Integration

The dashboard's kind toggle becoming **registry-driven** (so `cursor`/`opencode` appear with no
dashboard edit, including the OpenCode **NEW** badge) is owned by `custom-providers/01-spec.md`
§7. This spec does not re-specify that render. The two facts relevant here:

- `KindIcon` (verified at `DashboardView.tsx:36`, with claude `#d58fff`, codex `#5ccfe6`) gains
  an `opencode` case (brand glyph + the `#ffa657` color from `01-spec.md`'s `HARNESSES` table),
  per `01-spec.md` §7. Fallback to the existing `Terminal` glyph for unknown kinds.
- Selecting **OpenCode** sets `kind = "opencode"` and calls the unchanged
  `createSession(name, "opencode", …)`. There is **no** `<catalogId>` kind and **no** `provider`
  payload to stash — the OpenCode _provider_ (Anthropic, OpenRouter, …) was already chosen in the
  Harnesses → OpenCode settings tab and recorded in OpenCode's config, not at session-create time.

This is also why the client `SessionKind` must come from the shared registry source (§4.1): a
stale closed-union `SessionKind` in `useSessions.ts` would reject `kind = "opencode"` in exactly
this `createSession` path.

---

## 10. Backward Compatibility & Migration

1. `bash` / `claude` / `codex` are untouched — same binaries, same `commandForHarness` output
   for them (byte-identical to today's `commandForKind`, per `01-spec.md` §3.4). No data
   migration for existing `ai-sessions.json` records.
2. `SessionKind` widens to the open id set (`01-spec.md` §3.5); existing guards still accept the
   three legacy literals and now also accept `opencode`/`cursor`. The duplicate union in
   `useSessions.ts` is removed so the client agrees (§4.1).
3. `SessionMeta` is structurally unchanged — no new `provider` sub-record; `kind: "opencode"` is
   the only addition an OpenCode session carries.
4. The picker is inert until OpenCode is configured — zero behavior change for users who only
   use bash/claude/codex. There is no HTTP path to be inert.
5. Repo config is opt-in: if `.terminalx/settings.toml` is absent, only User-scope settings
   apply, degrading to built-in defaults (env > repo TOML > user TOML > built-ins, per
   `01-spec.md` §6.3), mirroring `workspace-config.spec.md`'s "handle missing config gracefully".

---

## 11. Security Considerations

| Threat                          | Mitigation                                                                                                                                                                                                                                                                       |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Secret in committed repo config | `.terminalx/settings.toml` stores **only** non-secret keys (`[harness.opencode] providers`/`models`/`bin`). TerminalX holds **no** provider secret at all — auth is delegated to OpenCode's config / `.env` (`01-spec.md` §4.2). There is no `data/provider-credentials/` vault. |
| Secret in process list          | The launched command is always `opencode` with no key in argv; OpenCode reads its own credentials. TerminalX injects nothing (no `getEnvSetupCommands()` / `OPENAI_API_KEY` — neither exists in `src/`).                                                                         |
| Secret in logs / audit          | `audit()` records only the session kind (`opencode`), never a provider key.                                                                                                                                                                                                      |
| Arbitrary session kind          | `isValidHarnessId(kind)` requires the id to be a known registry harness (`01-spec.md` §3.3).                                                                                                                                                                                     |
| Untrusted gateway URL           | The gateway endpoint is written into OpenCode's config; if TerminalX surfaces an edit field, validate it is `https://` (allow `http://localhost` for dev) and warn on non-TLS. TerminalX never connects to it.                                                                   |
| Path traversal                  | Reuse `assertNotSensitivePath`/`resolveSafePath` (already used by the sessions route) for the executable-path field.                                                                                                                                                             |

---

## 12. Implementation Checklist

> The harness registry (`src/lib/harnesses/types.ts`, `registry.ts`, `command.ts`, `status.ts`),
> the `GET /api/harnesses` family, the Harnesses settings shell, and the dashboard's
> registry-driven toggle are **owned by `custom-providers/01-spec.md`** (§11 file-change summary)
> and are not re-listed here. This spec assumes they land first. There is **no**
> `src/lib/providers/` or `src/app/api/providers/` (verified — both absent) and **no**
> `providerRegistry` (the real surface is `listHarnesses`/`getHarness`/`isValidHarnessId`).

### OpenCode provider catalog (this spec — extends an `01-spec.md` file)

- [ ] `src/lib/harnesses/opencode-providers.ts` — **extend** the existing `OpenCodeProviderEntry`
      (`brands`/`featured`/`endpointEditable`/`docsUrl`), keep the 7 featured ids/labels and
      `TOTAL_OPENCODE_PROVIDERS = 96`, add `ConfiguredOpenCodeProvider`. No bundled 96-entry JSON
      (the tail is fetched lazily, `01-spec.md` §5.2).

### Session wiring (consume registry; fix client drift)

- [ ] `src/hooks/useSessions.ts` — **remove** the duplicate `SessionKind` union (line 5; used at
      21/45/76) and import the shared open `SessionKind`/`HARNESS_IDS` from `01-spec.md`'s source
      so `kind = "opencode"` is accepted on the client (§4.1).
- [ ] `src/lib/ai-sessions.ts` / `src/app/api/sessions/route.ts` — **no new change in this spec**;
      the open `SessionKind`, `commandForHarness`, and `isValidHarnessId` plumbing is owned by
      `01-spec.md` §3/§8. (Listed only so the dependency is explicit.)

### API (this spec — extends an `01-spec.md` route)

- [ ] `src/app/api/harnesses/opencode/providers/route.ts` — **extend** the read shape with the
      picker fields (featured 7 + 96 total, `?all=1&q=`); `POST` writes the provider stanza into
      OpenCode config + mirrors non-secret keys to `.terminalx/settings.toml`. No
      `/api/providers/catalog` or `/api/providers/config` route (rejected — see §8).

### UI (this spec)

- [ ] `ProvidersPickerModal` (title "Providers", "Search providers", 7 rows, "View all
      providers (96)") — the picker opened from the OpenCode tab's "Add your first provider".
- [ ] `ProviderConfigForm` (field matrix §6.1 — gateway endpoint + model only; no key/effort field).
- [ ] OpenCode panel's Providers/Models counts update after save.
- [ ] (The `ScopeTabs`, `HarnessTabs`, `OpenCodePanel`, and "Edit settings.toml" affordance are
      `01-spec.md` §6 deliverables; this spec only fills in the picker + config form they open.)

### Tests

- [ ] Catalog: exactly 7 featured in order; total 96; no `chatgpt`/`gemini`/`ollama` ids.
- [ ] Search filters across all 96 by label + brands.
- [ ] Launching OpenCode emits the byte-identical `bash -lc 'opencode; …; exec bash -l'` wrapper
      (`01-spec.md` §3.4) — no `terminalx-chat`, no `--model`/key in argv.
- [ ] `isValidHarnessId` accepts `opencode` (and the legacy literals); rejects unknown strings.
- [ ] `useSessions.ts` no longer redeclares `SessionKind`; `kind = "opencode"` round-trips
      client→server without being rejected.
- [ ] Repo save writes `[harness.opencode]` keys to `.terminalx/settings.toml` with **no** secret
      and **no** TerminalX-owned credential file (there is none).

---

## 13. Open Questions

1. Should the 96-entry provider list be refreshed at runtime (the OpenCode-style "Refresh" in
   the Advanced block) or pinned per release? Conductor shows a "Refresh" — the lazy fetch in
   `GET /api/harnesses/opencode/providers` (`01-spec.md` §8.4) could back it.
2. How does the full 96-entry list get resolved server-side — via the `opencode` CLI's own
   provider index, or a pinned snapshot? (`01-spec.md` §5.2 says fetched lazily; the exact source
   is left to the OpenCode route implementation.)
3. Multiple instances of one OpenCode provider (e.g. two OpenRouter endpoints) — OpenCode's own
   config governs whether this is allowed; the TerminalX picker currently assumes
   one-row-per-provider. Defer to OpenCode's config model rather than inventing a TerminalX
   instance id.

---

## 14. Cross-References

- **Harness registry, `HarnessDescriptor`, `commandForHarness`, `isValidHarnessId`, the
  Harnesses settings shell, `.terminalx/settings.toml`, and the `/api/harnesses` route family:**
  `custom-providers/01-spec.md` (this spec builds directly on it; does not redefine it). Its
  `00-corrections.md` records why the `AIProvider` interface, the `providerRegistry`, and the
  `data/provider-credentials/credentials.json` vault were removed — none of which this spec
  reintroduces.
- **Effort + the Default/Review model split:** `model-settings.spec.md` and the Models page
  (Default model / Review model rows). Effort is a Models-page concern, not an OpenCode-provider
  one.
- **Review model (separate from authoring):** `pr-review/01-ui-spec.md` and the Models page
  "Review model" row.
- **Repo config + injected port + setup/run:** `workspace-config.spec.md`
  (`.terminalx/settings.toml`, `TERMINALX_PORT` ← Conductor `CONDUCTOR_PORT`).
- **Verified code anchors:** `src/lib/ai-sessions.ts` (`SessionKind`:6, `CLI_BINS`:110,
  `commandForKind`:128, `isValidKind`:139), `src/hooks/useSessions.ts:5` (duplicate `SessionKind`,
  to be removed), `src/app/api/sessions/route.ts`, `src/components/dashboard/DashboardView.tsx`
  (`KindIcon`:36), `src/components/settings/SettingsView.tsx` (`Section`:38, `Row`:58),
  `src/lib/git-worktree.ts` (`TERMINALX_WORKTREES_ROOT`:55), `src/lib/secure-dir.ts`
  (`ensureSecureDir`:7). There is **no** `src/lib/providers/`, `src/app/api/providers/`,
  `providerRegistry`, `getEnvSetupCommands`, or `OPENAI_API_KEY` in the repo (all verified absent).

---

End of Specification
