import * as fs from "fs";
import * as path from "path";
import { ensureSecureDir } from "./secure-dir";

export interface Snippet {
  id: string;
  name: string;
  command: string;
  description?: string;
  createdAt: string;
  createdBy?: string;
}

const MAX_NAME = 80;
const MAX_COMMAND = 4000;
const MAX_DESCRIPTION = 200;
const MAX_SNIPPETS = 500;

function dataDir() {
  return path.join(process.cwd(), "data");
}

function snippetsFile() {
  return path.join(dataDir(), "snippets.json");
}

function ensureDataDir() {
  ensureSecureDir(dataDir());
}

let writeLock: Promise<void> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeLock.then(fn, fn);
  writeLock = next.then(
    () => {},
    () => {}
  );
  return next;
}

function atomicWrite(snippets: Snippet[]) {
  ensureDataDir();
  const file = snippetsFile();
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(snippets, null, 2), {
    encoding: "utf-8",
    mode: 0o600,
  });
  fs.renameSync(tmp, file);
}

export function listSnippets(): Snippet[] {
  ensureDataDir();
  const file = snippetsFile();
  if (!fs.existsSync(file)) return [];
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8")) as Snippet[];
  } catch {
    return [];
  }
}

export async function createSnippet(input: {
  name: string;
  command: string;
  description?: string;
  createdBy?: string;
}): Promise<Snippet> {
  return withLock(async () => {
    const name = input.name.trim();
    const command = input.command;
    if (!name) throw new Error("Name required");
    if (name.length > MAX_NAME) throw new Error("Name too long");
    if (!command) throw new Error("Command required");
    if (command.length > MAX_COMMAND) throw new Error("Command too long");
    if (input.description && input.description.length > MAX_DESCRIPTION) {
      throw new Error("Description too long");
    }

    const snippets = listSnippets();
    if (snippets.length >= MAX_SNIPPETS) {
      throw new Error("Snippet limit reached");
    }
    const snippet: Snippet = {
      id: crypto.randomUUID(),
      name,
      command,
      description: input.description?.trim() || undefined,
      createdAt: new Date().toISOString(),
      createdBy: input.createdBy,
    };
    snippets.push(snippet);
    atomicWrite(snippets);
    return snippet;
  });
}

export function getSnippet(id: string): Snippet | undefined {
  return listSnippets().find((s) => s.id === id);
}

export async function deleteSnippet(id: string): Promise<void> {
  return withLock(async () => {
    const snippets = listSnippets();
    const idx = snippets.findIndex((s) => s.id === id);
    if (idx === -1) throw new Error("Not found");
    snippets.splice(idx, 1);
    atomicWrite(snippets);
  });
}
