#!/usr/local/bin/node

import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { join } from "node:path";

const MAX_ENTRIES = 1_000_000;
const MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024;
const PRIVATE_PEM =
  /-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/_=-]{16}/;
const SKIPPED_MOUNTS = new Set(["/dev", "/proc", "/sys"]);

export function auditFinalRootfs(root = "/") {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    process.argv.length !== 2 ||
    root !== "/" ||
    realpathSync.native(root) !== root
  ) {
    throw new TypeError();
  }
  const pending = [root];
  let entries = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    if (!directory) throw new TypeError();
    for (const name of readdirSync(directory).sort()) {
      if (name === "." || name === ".." || name.includes("/")) throw new TypeError();
      const path = directory === "/" ? `/${name}` : join(directory, name);
      if (++entries > MAX_ENTRIES) throw new TypeError();
      const status = lstatSync(path);
      if (status.isSymbolicLink()) continue;
      if (status.isDirectory()) {
        if (!SKIPPED_MOUNTS.has(path)) pending.push(path);
        continue;
      }
      if (!status.isFile()) continue;
      if ((status.mode & 0o6000) !== 0 || status.size < 0 || status.size > MAX_FILE_BYTES) {
        throw new TypeError();
      }
      assertNoPrivatePem(path, status);
    }
  }
}

function assertNoPrivatePem(path, status) {
  let descriptor = -1;
  const chunk = Buffer.alloc(64 * 1024);
  let carry = "";
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== status.dev ||
      opened.ino !== status.ino ||
      opened.size !== status.size ||
      opened.mtimeMs !== status.mtimeMs
    ) {
      throw new TypeError();
    }
    let offset = 0;
    while (offset < opened.size) {
      const count = readSync(
        descriptor,
        chunk,
        0,
        Math.min(chunk.byteLength, opened.size - offset),
        offset
      );
      if (count < 1) throw new TypeError();
      const text = carry + chunk.subarray(0, count).toString("latin1");
      if (PRIVATE_PEM.test(text)) throw new TypeError();
      carry = text.slice(-256);
      offset += count;
    }
  } finally {
    chunk.fill(0);
    if (descriptor >= 0) closeSync(descriptor);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    auditFinalRootfs();
  } catch {
    process.stderr.write("TerminalX final root filesystem audit failed closed\n");
    process.exitCode = 1;
  }
}
