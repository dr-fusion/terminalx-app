import * as fs from "fs";
import * as path from "path";
import { ensureSecureDir } from "./secure-dir";

function recordingsDir() {
  return path.join(process.cwd(), "data", "recordings");
}

function ensureDir() {
  ensureSecureDir(recordingsDir());
}

function sanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.\-]/g, "_");
}

export function isRecordingEnabled(): boolean {
  return process.env.TERMINUS_RECORD_SESSIONS === "true";
}

export interface Recorder {
  id: string;
  file: string;
  write: (data: string) => void;
  close: () => void;
}

export function startRecorder(opts: {
  sessionId: string;
  username?: string;
  cols: number;
  rows: number;
}): Recorder | null {
  if (!isRecordingEnabled()) return null;
  ensureDir();
  const started = Date.now();
  const id = `${sanitize(opts.sessionId)}-${started}`;
  const file = path.join(recordingsDir(), `${id}.jsonl`);
  const stream = fs.createWriteStream(file, { flags: "a", mode: 0o600 });
  const header = {
    v: 1,
    sessionId: opts.sessionId,
    username: opts.username,
    startedAt: new Date(started).toISOString(),
    cols: opts.cols,
    rows: opts.rows,
  };
  stream.write(JSON.stringify(header) + "\n");

  let lastErrored = false;
  return {
    id,
    file,
    write(data: string) {
      if (lastErrored) return;
      const entry = { t: Date.now() - started, d: data };
      try {
        stream.write(JSON.stringify(entry) + "\n");
      } catch {
        lastErrored = true;
      }
    },
    close() {
      return new Promise<void>((resolve) => {
        try {
          stream.end(() => resolve());
        } catch {
          resolve();
        }
      });
    },
  };
}

export interface RecordingMeta {
  id: string;
  file: string;
  sessionId: string;
  createdBy?: string;
  startedAt: string;
  sizeBytes: number;
}

export function listRecordings(): RecordingMeta[] {
  ensureDir();
  const entries = fs.readdirSync(recordingsDir());
  const out: RecordingMeta[] = [];
  for (const name of entries) {
    if (!name.endsWith(".jsonl")) continue;
    const full = path.join(recordingsDir(), name);
    try {
      const stat = fs.statSync(full);
      const firstLine = readFirstLine(full);
      const header = firstLine ? JSON.parse(firstLine) : {};
      out.push({
        id: name.replace(/\.jsonl$/, ""),
        file: name,
        sessionId: header.sessionId ?? "",
        createdBy: header.username || undefined,
        startedAt: header.startedAt ?? new Date(stat.mtimeMs).toISOString(),
        sizeBytes: stat.size,
      });
    } catch {
      // skip malformed
    }
  }
  return out.sort((a, b) => (a.startedAt < b.startedAt ? 1 : a.startedAt > b.startedAt ? -1 : 0));
}

export function getRecordingMeta(id: string): RecordingMeta | null {
  const file = getRecordingPath(id);
  if (!file) return null;
  try {
    const stat = fs.statSync(file);
    const firstLine = readFirstLine(file);
    const header = firstLine ? JSON.parse(firstLine) : {};
    return {
      id,
      file: `${id}.jsonl`,
      sessionId: header.sessionId ?? "",
      createdBy: header.username || undefined,
      startedAt: header.startedAt ?? new Date(stat.mtimeMs).toISOString(),
      sizeBytes: stat.size,
    };
  } catch {
    return null;
  }
}

function readFirstLine(file: string): string | null {
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(8192);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    const text = buf.slice(0, n).toString("utf-8");
    const idx = text.indexOf("\n");
    return idx === -1 ? text : text.slice(0, idx);
  } finally {
    fs.closeSync(fd);
  }
}

export function getRecordingPath(id: string): string | null {
  const safe = sanitize(id);
  if (safe !== id) return null;
  const file = path.join(recordingsDir(), `${safe}.jsonl`);
  if (!fs.existsSync(file)) return null;
  return file;
}

/**
 * Delete recordings older than TERMINUS_RECORDING_RETENTION_DAYS.
 * Called once at server startup. 0/unset disables retention (keep forever).
 */
export function sweepExpiredRecordings(): { deleted: number } {
  const raw = process.env.TERMINUS_RECORDING_RETENTION_DAYS;
  const days = raw ? parseInt(raw, 10) : 0;
  if (!Number.isFinite(days) || days <= 0) return { deleted: 0 };

  const dir = recordingsDir();
  if (!fs.existsSync(dir)) return { deleted: 0 };

  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  let deleted = 0;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith(".jsonl")) continue;
    const full = path.join(dir, name);
    try {
      const stat = fs.statSync(full);
      if (stat.mtimeMs < cutoff) {
        fs.unlinkSync(full);
        deleted++;
      }
    } catch {
      // skip
    }
  }
  return { deleted };
}
