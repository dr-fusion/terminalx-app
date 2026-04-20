import * as fs from "fs";

/**
 * Ensure a directory exists with 0o700 perms, chmod'ing if it pre-exists with
 * wider perms. Silently no-op on platforms without POSIX perms (Windows).
 */
export function ensureSecureDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") {
    try {
      fs.chmodSync(dir, 0o700);
    } catch {
      // Best-effort; a failing chmod shouldn't break startup.
    }
  }
}
