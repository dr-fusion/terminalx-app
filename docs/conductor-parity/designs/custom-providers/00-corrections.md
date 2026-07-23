# Corrections — custom-providers design set

## 2026-07-23 LocalTmux permission-safety correction

The implemented LocalTmux launcher no longer exposes or consumes
`dangerouslySkipPermissions`, and Codex no longer has a default `--yolo`
argument. `POST /api/sessions` rejects the legacy field when it is `true` before
any side effect. This correction supersedes every skip-permissions UI, payload,
`optionFlags`, and command example in the June design documents.

This is intentionally a product-launch claim, not a process-isolation claim.
LocalTmux launches the bare trusted local CLI (plus validated model/plan
arguments), so user and Project CLI configuration remains local operator
authority. Existing tmux processes also retain their original arguments and
must be stopped and recreated after upgrading. A future hosted bypass mode must
be a separate, explicitly confirmed mode inside a verified isolated Sandbox.

**Date:** 2026-06-25
**Backs:** GitHub issue #4
**Authoritative source:** the Conductor screenshots (Harnesses page, OpenCode tab, Providers picker modal) and the real TerminalX repo (`src/lib/ai-sessions.ts`, `src/app/api/sessions/route.ts`, `src/components/dashboard/DashboardView.tsx`, `src/components/settings/SettingsView.tsx`).

`01-spec.md` has been rewritten from scratch to match both. Documents `02`–`06` were drafted **without** the screenshots and contradict ground truth in the ways listed below. They should be treated as superseded by `01-spec.md` and either deleted or rewritten to follow it.

---

## Cross-cutting errors (present in 02, 03, 04, 05, 06)

1. **Invented "AIProvider" class hierarchy.** All of `02`–`06` are built around an `AIProvider` interface (`AIProviderConfig` + `AIProviderRuntime`, 7 methods: `invokeCommand`, `validateInstallation`, `validateCredentials`, `getEnvSetupCommands`, `getAuthHelpText`, etc.) and concrete classes `ClaudeProvider` / `CodexProvider` / `OpenCodeProvider`. **None of this exists in Conductor's UI**, which is organized as **Harnesses** (Claude Code / Codex / Cursor / OpenCode) — a flat, data-driven tab list, not a per-provider OO contract. `01-spec.md` replaces it with a plain `HarnessDescriptor` table refactor of the real `CLI_BINS` / `commandForKind`.

2. **"Provider" vs "Harness" naming.** Conductor's settings page is titled **"Harnesses"**; "Providers" in Conductor is the _nested_ picker **inside the OpenCode harness** (the 96-provider list), not the top-level concept. The docs conflate the two and use "provider" for the top-level abstraction throughout.

3. **Invented credential vault.** `02`, `03`, `04`, `06` specify storing secrets in `data/provider-credentials/credentials.json` (mode 0600) with `saveCredential`/`deleteCredential`/`getCredentials`, and `04` lists "Credential Isolation" as a key design decision. The real Conductor flow delegates auth to the **CLI** ("Run claude /login", a "Connected" pill, a Provider/Plan/Org/Account table) or an **API key**, and TerminalX is env-driven (`ANTHROPIC_API_KEY`, `.env`, `TERMINUS_*`). No bespoke vault exists or is shown. `01-spec.md` removes it.

4. **Missing the CLI-vs-API-key Authentication UI.** No doc describes Conductor's Claude Code tab: the two large **CLI** / **API key** choices (terminal vs key icon, ✓ on the active one), the green **"Connected"** pill, the **Provider / Plan / Org / Account** table, or the **"Run claude /login"** button. This is the single most important screen for this feature and was entirely absent.

5. **Missing harnesses that are actually in the screenshots.** The real tab set is **Claude Code, Codex, Cursor, OpenCode (NEW badge)**. The docs never mention **Cursor**, never mention the **NEW** badge on OpenCode, and instead invent unrelated runtimes (see #7).

6. **"Open Code" mislabeled and misunderstood.** Throughout the docs it is written **"Open Code"** (two words) and described as a generic _"Multi-Model"_ provider that TerminalX would drive via API key/config JSON at `~/.opencode/config.json`. Ground truth: it is **OpenCode** — "The open source AI coding agent" — a **harness whose tab hosts its own Providers (0 configured → Add your first provider) and Models (0 selected) registry**, an **Advanced** block with an **"Installed 1.17.7"** version pill / Open-in-Finder / Docs / Refresh, and an **"OpenCode executable path"** override (placeholder `/usr/local/bin/opencode`, "Leave empty to use the bundled version"). None of these real UI elements appear in the docs.

7. **Invented the canonical provider list.** `04`/`05`/`06` (and the old `01`) seed providers/models like **OpenAI GPT-4/3.5, Google Gemini, Ollama (llama2/mistral), custom-http, custom-cli** as if they were TerminalX's own runtimes. The real Providers modal lists, verbatim: **OpenCode Go / OpenCode Zen, OpenAI, GitHub Copilot / GitHub Models, Anthropic, Google, Vercel AI Gateway, OpenRouter**, with a **"View all providers (96)"** footer — and these are _OpenCode's_ providers, configured into OpenCode's config, **not** runtimes TerminalX speaks to over HTTP.

8. **No User/Repo scope split, no `settings.toml`.** The docs omit Conductor's **User vs Repo** scope tabs and the repo-scoped **"Edit settings.toml"** button backed by a committed `.conductor/settings.toml`. `01-spec.md` adds the TerminalX analog (`.terminalx/settings.toml`, env > repo TOML > user TOML > built-ins).

---

## Per-document notes

### 02-api-reference.md

- Entire document documents the fictional `AIProvider` interface (`readonly id/label/type`, `authType: "none"|"api-key"|"oauth"|"device-flow"`, `invokeCommand(options)`, `validateCredentials()`, etc.). Superseded by `HarnessDescriptor` + `commandForHarness` + `probeHarness` in `01-spec.md` §3–§4.
- Lists `authType: "device-flow"` as Claude's method; the screenshots show a **CLI vs API key** toggle, not an OAuth/device-flow abstraction at this layer.
- No mention of the real new routes (`GET /api/harnesses`, `/api/harnesses/[id]/login`, `/api/harnesses/opencode/providers`).

### 03-implementation.md

- "Step 1: Create `src/lib/providers/opencode.ts` … `class OpenCodeProvider implements AIProvider`" — wrong abstraction and wrong path (no `src/lib/providers/` exists; the refactor target is `src/lib/ai-sessions.ts` → new `src/lib/harnesses/`).
- Uses `execSync("which open-code …")` and a `~/.opencode/config.json` `{apiKey, provider, model}` shape that does not match OpenCode's real "providers/models/advanced/executable-path" UI.
- Repeats the "Open Code (Multi-Model)" mislabel.

### 04-design-summary.md

- "Key Design Decisions" #1 (Interface-Driven, 7 methods), #2 (Config/Runtime split), #4 (Credential Isolation in `data/provider-credentials/`), #6 (Registry of `AIProvider` objects) all describe the fictional architecture.
- Architecture diagram nodes `CreateSessionDialog` and `ProviderSettingsPanel` do not exist; the real surfaces are `DashboardView.tsx` (kind toggle) and `SettingsView.tsx` (`Section`/`Row` blocks). There is no separate "CreateSessionDialog" component.

### 05-quick-reference.md

- "AIProvider Interface (7 Methods)" and the `providerRegistry.list/get/getConfigured/getDefault/register/refreshAvailability()` API are fictional. The real registry surface is `listHarnesses` / `getHarness` / `isValidHarnessId` (`01-spec.md` §3.3).
- Example ids/labels ("Claude 3.5 Sonnet", "GPT-4 (OpenAI)", "Ollama Local (Mistral)") mix model-level naming into what is actually harness-level selection.

### 06-providers-overview.md

- Index links to non-existent files (`PROVIDER_DESIGN_SUMMARY.md`, `PROVIDER_SPEC.md`, `PROVIDER_IMPLEMENTATION.md`, `PROVIDER_API_REFERENCE.md`) — the actual files are `01`–`05` in this folder.
- "Use Cases" / "File Changes Summary" reference `src/lib/providers/*`, `ProviderSettingsPanel.tsx`, `CreateSessionDialog`, and `data/provider-credentials/credentials.json` — none of which match the real repo or the real UI.
- States "Built-in Support: Claude and Codex" and "example provider: Open Code" but omits **Cursor** and mislabels **OpenCode**, and never surfaces the CLI/API-key auth, the Connected/account table, or the 96-provider picker.

---

## What `01-spec.md` fixed (summary)

- Replaced the `AIProvider` class hierarchy with a data-driven **harness registry** that directly refactors the real `CLI_BINS` / `commandForKind` / `isValidKind` and preserves the exact `bash -lc '…; exec bash -l'` wrapper.
- Documented the real **Harnesses** tabs (Claude Code / Codex / Cursor / OpenCode **NEW**), the **CLI vs API key** authentication, the **Connected** pill + **Provider/Plan/Org/Account** table, and **"Run claude /login"**.
- Modeled the **OpenCode** harness correctly: nested Providers (0 configured → Add your first provider) and Models (0 selected) registries, the featured 7 providers + **96** total, and the Advanced block (Installed `1.17.7` pill, Open in Finder, Docs, Refresh, executable-path override).
- Removed the invented credential vault; auth stays delegated to CLIs + `.env`.
- Added the **User/Repo scope** split and the committed **`.terminalx/settings.toml`** ("Edit settings.toml" analog).
