# TerminalX backup, restore, and restore drills

TerminalX stores all durable authority — Team Sessions, canonical identity,
connections, mobile auth, the Phase 10 event hash chain, and the Phase 9
accounting ledgers — in a single SQLite database (default
`data/team-sessions.sqlite`). Backing up that one file backs up everything.

## Safety guarantees

- Backups use SQLite's **Online Backup API** (`backupSqliteDatabase`), which
  produces a single, transactionally-consistent file even while the database is
  open under WAL. **Never** `cp` a live `-wal`/`-shm`/`.sqlite` set by hand — that
  can capture a torn, unrecoverable state.
- Pre-migration snapshots use `VACUUM INTO`, which is likewise consistent under
  WAL.
- All artifacts are written mode `0600`. The database stores only digests and
  opaque credential handles — no plaintext secrets — so backups carry no secret
  material.

## Automatic backups

The server maintenance loop takes a rotated online backup on a cadence
(`TERMINALX_BACKUP` interval, default every 6 h) into `data/backups/full`, and
prunes expired recordings on the same cadence. Retention:

- `TERMINALX_BACKUP_KEEP` (default 14) full backups.
- `TERMINALX_PRE_MIGRATION_SNAPSHOT_KEEP` (default 10) pre-migration snapshots.

## Manual backup

```ts
import { backupTeamSessionDatabase } from "@/lib/ops/backup";
await backupTeamSessionDatabase(); // → data/backups/full/team-sessions.backup.<ts>.sqlite
```

Or point it explicitly:

```ts
await backupTeamSessionDatabase({ sourcePath, backupDir, keep });
```

Verify any backup before trusting it:

```ts
import { verifyBackup } from "@/lib/ops/backup";
verifyBackup(backupPath); // { ok, applicationOk, integrityOk, schemaVersion }
```

## Pre-migration snapshots

Every schema migration is preceded by an automatic, fail-closed snapshot: the
migration dispatcher (`openTeamSessionDatabase`) takes a `VACUUM INTO` snapshot
into `data/backups/pre-migration/` **before** any migration mutates the database.
If the snapshot cannot be written, the migration is refused and the server does
not start — you never migrate without a recovery point. These snapshots are the
artifact a migration-aware rollback restores from (`canary-rollback.md`).

## Restore

Restore is an **offline** operation — stop the server first so no live
connection holds the target.

```ts
import { restoreSqliteDatabase } from "@/lib/ops/backup";
restoreSqliteDatabase(backupPath, "data/team-sessions.sqlite");
```

`restoreSqliteDatabase` verifies the backup, removes any stale
`-wal`/`-shm`/`-journal` sidecars at the target, copies the self-contained
backup into place `0600`, and re-verifies. It throws (fails closed) if the backup
does not verify. Then start the server; readiness confirms the schema and
integrity.

## Restore drills

Prove recoverability, don't assume it. The restore drill backs up the live
database, restores the backup into a throwaway location, and verifies the
restored copy end-to-end — integrity, schema, and the Phase 10 event hash chain
over **every** session:

```ts
import { runRestoreDrill } from "@/lib/ops/restore-drill";
const result = await runRestoreDrill(); // { ok, sessionsVerified, chainFailures, ... }
```

Run a drill on a schedule and after any upgrade. A non-empty `chainFailures`
means the restored database's tamper-evident chain does not verify — treat it as
a corruption incident (`runbooks.md#db-unavailable`). The drill only reads the
live database (via the online backup API); it never mutates it.

## Capacity controls (documented limits)

- `TERMINUS_MAX_SESSIONS` (default 20) — concurrent PTY sessions; surfaced as
  `terminalx_pty_sessions` and enforced at creation.
- WebSocket payload ceilings: 4 MB (terminal), 64 KB (logs/files).
- Container CPU/memory ceilings in `docker-compose.yml`; `LimitNOFILE` in systemd.
- Retention counts above bound backup/snapshot disk growth.
