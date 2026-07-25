import type { Writable } from "node:stream";

/** Transfer one sensitive buffer to a Writable and zero it only after ownership returns. */
export async function writeOwnedBuffer(output: Writable, bytes: Buffer): Promise<void> {
  try {
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error | null): void => {
        if (settled) return;
        settled = true;
        output.removeListener("error", onError);
        if (error) reject(error);
        else resolve();
      };
      const onError = (error: Error): void => finish(error);
      output.once("error", onError);
      try {
        output.write(bytes, (error) => finish(error));
      } catch (error) {
        finish(error instanceof Error ? error : new Error("write failed"));
      }
    });
  } finally {
    bytes.fill(0);
  }
}
