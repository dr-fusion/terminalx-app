# TerminalX Models & Harness Settings Page Specification

**Issue:** [#11](https://github.com/manish05/terminalx-app-mono/issues/11) — Models & harness settings page
**Labels:** feature, settings, configuration
**Effort:** Medium
**Depends on:** Custom AI Providers (`designs/custom-providers/`, issue #4) for the
provider/model registry; Extended Providers (`designs/extended-session-types.spec.md`,
issue #8) for the model catalog used to populate dropdowns.

> **Safety correction (2026-07-23):** LocalTmux no longer offers a
> skip-permissions control or request field and does not add Codex `--yolo`.
> References below describe the earlier implementation and are superseded by
> `custom-providers/00-corrections.md`.

## Overview

This spec defines a **Models** settings page (and the surrounding **Settings shell**) for
TerminalX, mirroring Conductor's Models page. Today, model/agent selection is a transient
per-session choice made in the new-session dialog (`DashboardView.tsx` lets you pick a
`SessionKind` of `bash | claude | codex` and, for `claude`, a "dangerously skip permissions"
toggle). There is **no persisted notion of a default model, a separate review model, an
effort level, a Codex personality, or default plan/fast modes** — and no User-vs-Repo scope
split for any settings.

This page introduces:

1. A **Settings shell** with **User** / **Repo** scope tabs and a left-nav (General, Account,
   Models, Harnesses, Environment, Git, Appearance, then a "More" group: Experimental,
   Advanced). This spec owns the **Models** entry; sibling specs own the others.
2. A **Models page** with: a **Default model** (model + effort), a **separate, independently
   configurable Review model** (model + effort), a **Codex personality** dropdown, and toggles
   for **Default to plan mode**, **Default to fast mode**, and **Use Claude Code with Chrome**.
3. A **persistence layer** (`GET`/`PUT /api/settings`) with **user** and **repo** scope, where
   repo scope is a committed TOML file (`.terminalx/settings.toml`, the analog of Conductor's
   `.conductor/settings.toml`).
4. Wiring so the persisted defaults **seed the new-session dialog** and **flow into command
   generation** (the review model is consumed by the PR-review surface, not session authoring).

---

## Conductor UI reference (from screenshots)

The authoritative UI facts this feature depends on, captured from the user's Conductor
screenshots. Any contradicting layout/naming is wrong.

### Settings shell (common to all settings screens)

- **Two top-level scope tabs:** `User` and `Repo`. Settings exist at both user scope and repo
  scope.
- **Left nav (User scope):** General, Account, Models, Harnesses (a "Providers" entry appears
  in one capture), Environment, Git, Appearance; then a **"More"** group: Experimental,
  Advanced.
- **Repo-scoped harness screens** show a top-right **"Edit settings.toml"** button — Conductor
  stores repo config in a committed TOML file (`.conductor/settings.toml`).

### Models settings page

- Title **"Models"**.
- **Default model** row = a model dropdown (e.g. "Opus 4.8 1M") + an **Effort** dropdown (e.g.
  "Effort high"); sublabel **"Model for new chats"**.
- **Review model** row = model dropdown + Effort dropdown; sublabel **"Model for code
  reviews"**. **IMPORTANT: code review uses a SEPARATE, independently-configurable model from
  authoring.**
- **Codex personality for new chats** = dropdown (e.g. "Pragmatic (default)"); sublabel **"Style
  to use when a new chat starts with a Codex model"**.
- **Default to plan mode** = toggle; sublabel **"Start new chats in plan mode"**.
- **Default to fast mode** = toggle; sublabel **"Start new chats in fast mode"**.
- **Use Claude Code with Chrome** = toggle + links to a Chrome extension and docs.

### Harnesses settings page (context; specced separately, referenced here for the left-nav)

- Title **"Harnesses"**. Sub-tabs, one per harness: **Claude Code**, **Codex**, **Cursor**,
  **OpenCode** (OpenCode carries a "NEW" badge). The model dropdowns on the Models page draw
  their options from these harnesses' available models (see §4).

### Cross-cutting takeaways

- Repo config lives in a committed TOML (`.conductor/settings.toml`); TerminalX's analog is a
  committed `.terminalx/settings.toml` with an **"Edit"** affordance, plus a **User-vs-Repo**
  scope split.
- Code review uses a **separate configurable model** — this page is where it is configured; the
  PR-review surface consumes it.

---

## 1. Data Model

### 1.1 Core settings types

```typescript
// src/lib/settings/types.ts  (new)

/** Effort levels offered in the "Effort" dropdowns. Conductor shows e.g. "Effort high". */
export type EffortLevel = "low" | "medium" | "high" | "max";

/** A model+effort pairing, used by both Default model and Review model rows. */
export interface ModelChoice {
  /**
   * Provider-qualified model id from the registry (custom-providers spec).
   * Examples: "claude:opus-4-8-1m", "codex:gpt-5-codex", "opencode:..."
   * `null` means "inherit" (repo scope falls back to user scope; user scope
   * falls back to the registry default).
   */
  modelId: string | null;

  /** Reasoning/effort level. `null` means inherit. */
  effort: EffortLevel | null;
}

/** Codex personality presets. "pragmatic" is the default (label "Pragmatic (default)"). */
export type CodexPersonality = "pragmatic" | "concise" | "thorough" | "friendly";

/**
 * The Models settings page payload. Every field is optional/nullable so that an
 * unset field at one scope transparently inherits from the lower-precedence scope.
 */
export interface ModelSettings {
  /** "Default model" row — model for new chats. */
  defaultModel: ModelChoice;

  /**
   * "Review model" row — model for code reviews. SEPARATE from defaultModel.
   * Consumed by the PR-review surface (designs/pr-review/), never by session authoring.
   */
  reviewModel: ModelChoice;

  /** "Codex personality for new chats". `null` inherits. */
  codexPersonality: CodexPersonality | null;

  /** "Default to plan mode" — start new chats in plan mode. `null` inherits. */
  defaultToPlanMode: boolean | null;

  /** "Default to fast mode" — start new chats in fast mode. `null` inherits. */
  defaultToFastMode: boolean | null;

  /** "Use Claude Code with Chrome". `null` inherits. */
  useClaudeCodeWithChrome: boolean | null;
}
```

### 1.2 Scoped settings envelope

```typescript
// src/lib/settings/types.ts  (continued)

export type SettingsScope = "user" | "repo";

/**
 * The full settings document for one scope. Models is the only section this spec
 * owns; sibling sections (harnesses, environment, git, appearance) are typed here
 * as opaque pass-through so a single file/route serves all settings pages.
 */
export interface ScopedSettings {
  /** Schema version for migrations. */
  version: 1;
  models?: Partial<ModelSettings>;
  // Reserved for sibling specs; preserved verbatim on read/write:
  harnesses?: Record<string, unknown>;
  environment?: Record<string, unknown>;
  git?: Record<string, unknown>;
  appearance?: Record<string, unknown>;
}

/**
 * The resolved, fully-defaulted Models settings the UI and command generation use.
 * Produced by merging registry defaults < user scope < repo scope (see §3.3).
 */
export interface ResolvedModelSettings {
  defaultModel: { modelId: string; effort: EffortLevel };
  reviewModel: { modelId: string; effort: EffortLevel };
  codexPersonality: CodexPersonality;
  defaultToPlanMode: boolean;
  defaultToFastMode: boolean;
  useClaudeCodeWithChrome: boolean;
  /** Per-field provenance so the UI can render "inherited from User" hints. */
  source: Record<keyof ModelSettings, SettingsScope | "default">;
}
```

### 1.3 Persistence locations

| Scope    | Location                                                                                           | Format | Committed?           | Conductor analog           |
| -------- | -------------------------------------------------------------------------------------------------- | ------ | -------------------- | -------------------------- |
| **User** | `<data>/settings/user.json` (`data/` dir, mode `0600`, same convention as `data/ai-sessions.json`) | JSON   | No (per-host)        | User scope settings        |
| **Repo** | `<repoRoot>/.terminalx/settings.toml`                                                              | TOML   | **Yes** (checked in) | `.conductor/settings.toml` |

- `<data>` is `path.join(process.cwd(), "data")`, matching `ai-sessions.ts`
  (`DATA_DIR`/`FILE`) and `provider-credentials` in the custom-providers spec.
- The repo file lives under the repository root resolved for the active session's
  worktree (`SessionMeta.worktree.repoRoot`, see `src/lib/ai-sessions.ts` and
  `src/lib/git-worktree.ts`). When no repo context is active, the Repo tab is disabled
  with a hint ("Open a session in a Git repo to edit repo settings").
- Repo writes are validated against `TERMINUS_ROOT` via the existing
  `resolveSafePath` / `assertNotSensitivePath` helpers in `src/lib/file-service.ts`
  before touching disk (same guard `git-worktree.ts` uses).

### 1.4 `.terminalx/settings.toml` example (repo scope)

```toml
# .terminalx/settings.toml — committed; analog of Conductor's .conductor/settings.toml
version = 1

[models.defaultModel]
modelId = "claude:opus-4-8-1m"
effort = "high"

[models.reviewModel]
modelId = "codex:gpt-5-codex"   # review model is independent of the authoring model
effort = "medium"

[models]
codexPersonality = "pragmatic"
defaultToPlanMode = true
defaultToFastMode = false
useClaudeCodeWithChrome = false
```

User scope is the same shape serialized as JSON in `data/settings/user.json`.

---

## 2. API

A single settings route serves both scopes; the Models page is one section of the payload.
Routes follow the existing Next.js App Router + `NextRequest`/`NextResponse` conventions
(see `src/app/api/telegram/settings/route.ts`) and use the `x-username` / `x-user-role`
request headers already injected by middleware.

### 2.1 `GET /api/settings`

```
GET /api/settings?scope=user
GET /api/settings?scope=repo&session=<sessionName>
```

- `scope` (required): `user | repo`.
- `session` (required for `scope=repo`): the session name whose `worktree.repoRoot`
  identifies the repo file (`getMeta(session)` from `ai-sessions.ts`).

**Response 200:**

```jsonc
{
  "scope": "repo",
  "settings": {
    "version": 1,
    "models": {
      /* Partial<ModelSettings> */
    },
  },
  "resolved": {
    /* ResolvedModelSettings — registry < user < repo merge */
  },
  "repoPath": "/abs/path/.terminalx/settings.toml", // repo scope only
  "exists": true, // false if file not yet created
}
```

- `404` if `scope=repo` and the session/repo cannot be resolved.
- `400` on invalid `scope`.
- Always returns `resolved` so the page can render even when the scoped file is empty.

### 2.2 `PUT /api/settings`

```
PUT /api/settings
Content-Type: application/json

{
  "scope": "user" | "repo",
  "session": "<name>",                 // required for repo scope
  "models": { /* Partial<ModelSettings> — only changed fields */ }
}
```

- Performs a **deep merge** of the supplied `models` patch into the scope's existing
  document, then validates and writes atomically (tmp + `fs.renameSync`, mirroring
  `atomicWrite` in `ai-sessions.ts`).
- Setting a field to `null` clears it (re-enabling inheritance).
- User scope → `data/settings/user.json`. Repo scope → `.terminalx/settings.toml`,
  preserving any non-`models` tables byte-for-byte (round-trip-safe TOML).
- Repo scope writes require a resolvable `repoRoot`; otherwise `409`.
- **Auth:** user scope is writable by the authenticated user. Repo scope is gated on
  `x-user-role === "admin"` (consistent with the admin-only Telegram config write in
  `src/app/api/telegram/settings/route.ts`); non-admins get `403`. Audit each repo write
  via `audit("settings_repo_updated", …)` using the `src/lib/audit-log.ts` helper. Note:
  `AuditEvent` in that file is a closed string-literal union that does **not** yet include
  `settings_repo_updated` (the Telegram route uses the existing `telegram_config_updated`),
  so this spec **adds** `settings_repo_updated` to the union — without that edit the call is
  a TypeScript compile error.

**Response 200:** `{ "settings": <ScopedSettings>, "resolved": <ResolvedModelSettings> }`.
**Errors:** `400` invalid body/effort/modelId, `403` repo write without admin,
`409` repo scope with no repo context, `500` write failure.

### 2.3 `GET /api/settings/models/options`

Populates the model dropdowns from the provider/model registry rather than a hard-coded list.

```jsonc
// GET /api/settings/models/options
{
  "models": [
    {
      "id": "claude:opus-4-8-1m",
      "label": "Opus 4.8 1M",
      "harness": "claude", // groups options by harness sub-tab
      "available": true, // CLI installed + configured (registry.getConfigured)
      "supportedEfforts": ["low", "medium", "high", "max"],
    },
    // ... codex, cursor, opencode entries
  ],
  "efforts": ["low", "medium", "high", "max"],
  "codexPersonalities": [
    { "id": "pragmatic", "label": "Pragmatic (default)" },
    { "id": "concise", "label": "Concise" },
    { "id": "thorough", "label": "Thorough" },
    { "id": "friendly", "label": "Friendly" },
  ],
}
```

- Backed by `providerRegistry.list()` + per-provider model metadata defined in the
  custom-providers spec (`AIProviderConfig.metadata.supportedModels`) and the extended
  catalog in `extended-session-types.spec.md`. Unavailable models are still listed but
  rendered disabled with the provider's `unavailableReason` as a tooltip, so a default can
  be configured before the CLI is installed.
- The **Review model** dropdown reuses this same list — it is independently selectable, not
  constrained to the Default model's choice.

---

## 3. Persistence library

```typescript
// src/lib/settings/store.ts  (new)

import * as fs from "fs";
import * as path from "path";
import { ensureSecureDir } from "@/lib/secure-dir";
import { resolveSafePath, assertNotSensitivePath } from "@/lib/file-service";
import type { ScopedSettings, ResolvedModelSettings } from "./types";

const DATA_DIR = path.join(process.cwd(), "data", "settings");
const USER_FILE = path.join(DATA_DIR, "user.json");
const REPO_REL = path.join(".terminalx", "settings.toml");

/** Read the user-scope JSON document (empty default if absent). */
export function readUserSettings(): ScopedSettings {
  /* ensureSecureDir + JSON.parse */
}

/** Atomically write user-scope settings (tmp + rename, mode 0600). */
export async function writeUserSettings(next: ScopedSettings): Promise<void> {
  /* … */
}

/** Resolve <repoRoot>/.terminalx/settings.toml, guarded against traversal. */
export function repoSettingsPath(repoRoot: string): string {
  const p = resolveSafePath(path.join(repoRoot, REPO_REL));
  assertNotSensitivePath(p);
  return p;
}

/** Parse repo TOML, preserving unknown tables for round-trip-safe writes. */
export function readRepoSettings(repoRoot: string): ScopedSettings {
  /* TOML.parse */
}
export async function writeRepoSettings(repoRoot: string, next: ScopedSettings): Promise<void> {
  /* … */
}
```

### 3.1 Concurrency

Reuse the serialized-write pattern from `ai-sessions.ts` (a module-level `writeLock`
promise chain via `withLock`) so concurrent `PUT`s don't interleave. Repo writes also take a
per-`repoRoot` lock.

### 3.2 TOML dependency

Add `@iarna/toml` (or `smol-toml`) for round-trip-safe parse/stringify. This is the only new
runtime dependency; it keeps non-`models` tables intact so the repo file can hold sibling
specs' sections.

### 3.3 Resolution (merge precedence)

`resolve(repoRoot?)` returns `ResolvedModelSettings`:

```
registry defaults  <  user scope  <  repo scope        (later wins per-field)
```

- Each field is resolved independently; a `null`/absent field falls through to the next-lower
  scope, and `source[field]` records where the winning value came from.
- Registry defaults: `defaultModel` = `providerRegistry.getDefault()` first available model at
  effort `high`; `reviewModel` defaults to the **same** model/effort **only until** the user
  picks one (they are stored and resolved separately); `codexPersonality = "pragmatic"`;
  `defaultToPlanMode = false`; `defaultToFastMode = false`; `useClaudeCodeWithChrome = false`.

---

## 4. UI

### 4.1 Settings shell

```
src/components/settings/
  SettingsShell.tsx          (new — scope tabs + left nav + content slot)
  SettingsScopeTabs.tsx      (new — "User" / "Repo")
  SettingsNav.tsx            (new — General … Appearance, "More": Experimental, Advanced)
  ModelsSettingsPage.tsx     (new — this spec)
  SettingsView.tsx           (existing — folded in under a nav entry; see §4.4)
```

```
SettingsShell
├── header  ── h1 "Settings"
├── SettingsScopeTabs   ── [ User | Repo ]            (Repo disabled w/o repo context)
├── SettingsNav (left)  ── General · Account · Models · Harnesses · Environment ·
│                           Git · Appearance · — More — · Experimental · Advanced
└── <content>
     └── ModelsSettingsPage   (when nav === "models")
```

- On the **Repo** scope, a top-right **"Edit settings.toml"** button opens
  `.terminalx/settings.toml` in the in-app file editor (the analog of Conductor's
  "Edit settings.toml"). Disabled / hidden on User scope.
- Reuse the existing dark-theme primitives from `SettingsView.tsx` (`Section`, `Row`, the
  `#0f1117` / `#1a1d24` / `#e6f0e4` palette, `lucide-react` icons) so the page matches the
  rest of the app; add a shadcn `Switch` for the toggles and `Select` for the dropdowns.

### 4.2 Models page layout

```
ModelsSettingsPage
├── Section "Default model"        sublabel "Model for new chats"
│    └── Row: <ModelSelect> + <EffortSelect>
├── Section "Review model"         sublabel "Model for code reviews"
│    └── Row: <ModelSelect> + <EffortSelect>     ← independent from Default model
├── Section "Codex personality for new chats"
│    │     sublabel "Style to use when a new chat starts with a Codex model"
│    └── <PersonalitySelect>  (default option labeled "Pragmatic (default)")
├── ToggleRow "Default to plan mode"   sublabel "Start new chats in plan mode"
├── ToggleRow "Default to fast mode"   sublabel "Start new chats in fast mode"
└── ToggleRow "Use Claude Code with Chrome"
     ├── <Switch>
     └── links: [Chrome extension ↗]  [Docs ↗]
```

Each row, when the resolved value is inherited rather than set at the current scope, shows a
muted hint: `inherited from User` / `default`, driven by `resolved.source[field]`.

### 4.3 Page component sketch

```typescript
// src/components/settings/ModelsSettingsPage.tsx
"use client";

import { useEffect, useState } from "react";
import type { SettingsScope, ModelSettings, ResolvedModelSettings } from "@/lib/settings/types";

export function ModelsSettingsPage({ scope, session }: { scope: SettingsScope; session?: string }) {
  const [resolved, setResolved] = useState<ResolvedModelSettings | null>(null);
  const [options, setOptions] = useState<{
    models: any[];
    efforts: string[];
    codexPersonalities: any[];
  } | null>(null);
  const [dirty, setDirty] = useState<Partial<ModelSettings>>({});
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    const q =
      scope === "repo" ? `scope=repo&session=${encodeURIComponent(session ?? "")}` : "scope=user";
    fetch(`/api/settings?${q}`)
      .then((r) => r.json())
      .then((d) => setResolved(d.resolved));
    fetch("/api/settings/models/options")
      .then((r) => r.json())
      .then(setOptions);
  }, [scope, session]);

  async function save() {
    setStatus("saving…");
    const res = await fetch("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope, session, models: dirty }),
    });
    const d = await res.json();
    if (!res.ok) return setStatus(d.error ?? "save failed");
    setResolved(d.resolved);
    setDirty({});
    setStatus("saved");
  }

  // renders the §4.2 layout; ModelSelect/EffortSelect read from `options`,
  // each field seeded from `resolved`, edits accumulated in `dirty`.
}
```

### 4.4 Migrating the existing settings view

The current `SettingsView.tsx` (server/host info, "you", terminal engine, mobile, telegram,
help) is reorganized under the new shell:

- **server/host + telegram + auth** → **Advanced** / **Account** nav entries (User scope).
- **terminal engine + mobile** → **Appearance** (User scope).
- **Models** is the new entry specced here.

The reorganization is mechanical (move existing `Section` blocks under nav routes); no
behavior of those sections changes.

---

## 5. Wiring the persisted defaults

### 5.1 New-session dialog seeding

`DashboardView.tsx` currently initializes `const [kind, setKind] = useState<SessionKind>("bash")`
and a `skipPermissions` toggle. With this spec it instead seeds from the resolved Models
settings:

- The dialog fetches `GET /api/settings?scope=repo&session=…` (falling back to user scope when
  no repo is selected) and pre-selects the **Default model** (`defaultModel.modelId` → its
  harness/kind) and **effort**.
- **Default to plan mode** and **Default to fast mode** pre-toggle the corresponding new-chat
  options.
- **Codex personality** pre-selects when the chosen model is a Codex model.
- The user can still override any of these per-session; overrides do **not** write back to
  settings.

### 5.2 Command generation

Until the provider registry (issue #4) lands, `commandForKind(kind, opts)` in
`src/lib/ai-sessions.ts` only knows `bash | claude | codex` and the `claude`-only
`--dangerously-skip-permissions` flag. This spec extends the session-create payload
(`POST /api/sessions`, currently `{ name, kind, dangerouslySkipPermissions, cwd, worktree }`)
with an optional resolved `modelId` / `effort` / `personality` / `planMode` / `fastMode`,
threaded into command generation per the extended catalog in
`extended-session-types.spec.md` (§3.2). When that registry is absent, the fields are accepted
and stored on `SessionMeta` but only `claude`/`codex` invocations are emitted (graceful
degradation), so this page ships independently of #4/#8.

### 5.3 Review model consumption

The **Review model** is **not** used for session authoring. The PR-review surface
(`designs/pr-review/`) reads `resolved.reviewModel` when launching a review run, so authoring
and review can diverge (e.g. author with Opus, review with a Codex model). This is the single
source of truth for "what model reviews code."

---

## 6. Acceptance Criteria

- [ ] A **Settings shell** renders **User** / **Repo** scope tabs and the left-nav (General,
      Account, Models, Harnesses, Environment, Git, Appearance, then More: Experimental,
      Advanced). The **Repo** tab is disabled with a hint when no repo context is active.
- [ ] On **Repo** scope, an **"Edit settings.toml"** affordance opens
      `.terminalx/settings.toml`.
- [ ] The **Models** page renders, in order: **Default model** (model + effort, sublabel
      "Model for new chats"); **Review model** (model + effort, sublabel "Model for code
      reviews"); **Codex personality for new chats** (sublabel about Codex models); **Default
      to plan mode**; **Default to fast mode**; **Use Claude Code with Chrome** (with extension + docs links).
- [ ] The **Review model is independently configurable** from the Default model and persists
      separately.
- [ ] Model dropdowns are populated from `GET /api/settings/models/options`
      (provider/model registry), grouped by harness, with unavailable models shown disabled.
- [ ] `GET /api/settings?scope=user` and `?scope=repo&session=…` return both the scoped
      document and a fully-`resolved` Models payload.
- [ ] `PUT /api/settings` deep-merges a `models` patch, writes atomically, clears a field when
      set to `null`, and round-trips repo TOML without dropping sibling tables.
- [ ] User-scope settings persist to `data/settings/user.json` (mode `0600`); repo-scope
      settings persist to a committed `.terminalx/settings.toml`.
- [ ] Repo-scope writes require admin (`x-user-role`), are path-validated against
      `TERMINUS_ROOT`, and are audited.
- [ ] Resolution precedence is `registry defaults < user < repo`, per-field, with provenance
      surfaced as an "inherited from User"/"default" hint in the UI.
- [ ] The new-session dialog (`DashboardView.tsx`) seeds its model/effort/plan/fast/personality
      controls from the resolved defaults; per-session overrides do not write back.
- [ ] Invalid effort / unknown `modelId` / malformed body return `400`; repo scope with no repo
      context returns `409`.

---

## 7. Edge Cases

| Case                                                      | Behavior                                                                                                                                                                                                        |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Repo file does not exist yet                              | `GET` returns `exists: false` with `resolved` from registry+user; first `PUT` creates `.terminalx/` and the file.                                                                                               |
| Malformed `.terminalx/settings.toml`                      | `GET` returns `resolved` from registry+user, plus a `parseError` field; the page shows a non-blocking warning and an "Edit settings.toml" CTA. The file is **not** auto-rewritten (would clobber user content). |
| `modelId` references an uninstalled/removed model         | Value is retained verbatim; the dropdown shows it as a disabled "(unavailable)" option so it isn't silently lost; command generation falls back to bash per §5.2.                                               |
| Selected session has no `worktree.repoRoot` (non-Git cwd) | Repo tab disabled; repo `GET`/`PUT` return `409`.                                                                                                                                                               |
| Concurrent `PUT`s (two tabs)                              | Serialized via the `withLock` chain; last write wins per-field; response returns the merged result so each tab can reconcile.                                                                                   |
| Effort not in a model's `supportedEfforts`                | `PUT` rejects with `400`; the effort dropdown only offers the selected model's supported levels.                                                                                                                |
| Path traversal in repo path                               | Blocked by `resolveSafePath` + `assertNotSensitivePath` before any FS access.                                                                                                                                   |
| Non-admin edits repo scope                                | `PUT` returns `403`; the Repo tab's inputs render read-only with an "admin required" note (mirrors the Telegram section's admin gating).                                                                        |
| Review model never explicitly set                         | Resolves to the registry default but is stored/treated as a distinct field, so later changing the Default model does not change the Review model.                                                               |

---

## 8. Implementation Components & Files

| File                                             | Action | Purpose                                                                                                       |
| ------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------- |
| `src/lib/settings/types.ts`                      | new    | `ModelSettings`, `ModelChoice`, `EffortLevel`, `CodexPersonality`, `ScopedSettings`, `ResolvedModelSettings`. |
| `src/lib/settings/store.ts`                      | new    | Read/write user JSON + repo TOML, locking, atomic writes, path guards.                                        |
| `src/lib/settings/resolve.ts`                    | new    | `registry < user < repo` merge → `ResolvedModelSettings` with provenance.                                     |
| `src/app/api/settings/route.ts`                  | new    | `GET`/`PUT` for both scopes.                                                                                  |
| `src/app/api/settings/models/options/route.ts`   | new    | Dropdown options from the provider registry.                                                                  |
| `src/components/settings/SettingsShell.tsx`      | new    | Scope tabs + nav + content.                                                                                   |
| `src/components/settings/SettingsScopeTabs.tsx`  | new    | User/Repo tabs.                                                                                               |
| `src/components/settings/SettingsNav.tsx`        | new    | Left nav incl. "More" group.                                                                                  |
| `src/components/settings/ModelsSettingsPage.tsx` | new    | The Models page (§4.2).                                                                                       |
| `src/components/settings/SettingsView.tsx`       | edit   | Re-home existing sections under nav entries (§4.4).                                                           |
| `src/components/dashboard/DashboardView.tsx`     | edit   | Seed new-session controls from resolved defaults (§5.1).                                                      |
| `src/lib/ai-sessions.ts`                         | edit   | Carry `modelId`/`effort`/`personality`/`planMode`/`fastMode` on `SessionMeta`; command generation per §5.2.   |
| `src/lib/audit-log.ts`                           | edit   | Add `settings_repo_updated` to the `AuditEvent` union so the repo-write audit call (§2.2) type-checks.        |
| `package.json`                                   | edit   | Add a round-trip TOML library (`@iarna/toml` or `smol-toml`).                                                 |

### Verified codebase anchors

- `src/lib/ai-sessions.ts` — `SessionKind = "bash" | "claude" | "codex"`, `SessionMeta`
  (with optional `worktree.repoRoot`), `commandForKind`, the `DATA_DIR`/`FILE` + `atomicWrite`
  - `withLock` persistence pattern reused here.
- `src/lib/git-worktree.ts` — `worktreesBaseDir()` under `TERMINALX_WORKTREES_ROOT` /
  `<root>/.terminalx-worktrees`; `resolveSafePath`/`assertNotSensitivePath` usage that the
  repo-TOML path guard mirrors.
- `src/lib/file-service.ts` — `getTerminusRoot()` (`TERMINUS_ROOT` || `$HOME`),
  `resolveSafePath`, `assertNotSensitivePath`.
- `src/app/api/sessions/route.ts` — current `POST` body `{ name, kind,
dangerouslySkipPermissions, cwd, worktree }` and `commandForKind` call site that §5.2
  extends.
- `src/app/api/telegram/settings/route.ts` — the `GET`/`PATCH` settings-route shape,
  `x-user-role === "admin"` gating, and the `audit(...)` helper this spec mirrors. The route
  audits with `audit("telegram_config_updated", …)`.
- `src/lib/audit-log.ts` — the `audit(event, context)` helper and the **closed**
  `AuditEvent` union. The union does **not** contain `settings_repo_updated`; this spec edits
  the file to add it (see §8 files table) so the §2.2 repo-write audit call compiles.
- `src/components/settings/SettingsView.tsx` — existing `Section`/`Row` primitives and dark
  palette reused by the new pages; sections re-homed in §4.4.
- `src/components/dashboard/DashboardView.tsx` — current `kind`/`skipPermissions` new-session
  state seeded from resolved defaults in §5.1.

---

## 9. Estimated Effort

**Medium (3–5 days)**

- Settings types + store + resolution (user JSON + repo TOML, locking): ~1 day.
- `GET`/`PUT /api/settings` + options route: ~1 day.
- Settings shell (scope tabs, nav) + Models page UI: ~1.5 days.
- New-session seeding + `SessionMeta` carry-through + tests/docs: ~1 day.

## 10. Dependencies

- **Custom AI Providers** (`designs/custom-providers/`, #4) — provides
  `providerRegistry`/model metadata backing the dropdowns. This page degrades gracefully if it
  ships first (options list falls back to the current `claude`/`codex` kinds).
- **Extended Providers** (`designs/extended-session-types.spec.md`, #8) — the model catalog
  and `modelId`-aware command generation consumed in §5.2.
- **PR Review** (`designs/pr-review/`, #3) — consumer of the **Review model** (§5.3).
- New runtime dep: a round-trip-safe TOML library.
