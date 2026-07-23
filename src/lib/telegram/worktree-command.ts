import { isValidKind, type SessionKind } from "@/lib/ai-sessions";

export interface ParsedWorktreeCommand {
  directory: string;
  name?: string;
  kind: SessionKind;
}

function splitArgs(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;

  for (const ch of input.trim()) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        args.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current) args.push(current);
  return args;
}

export function slugifySessionName(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9 _.-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function autoWorktreeName(repoName = "repo", now = new Date()): string {
  const stamp = now
    .toISOString()
    .replace(/\.\d{3}Z$/u, "")
    .replace(/[-:T]/g, "")
    .toLowerCase();
  return slugifySessionName(`${repoName}-worktree-${stamp}`).slice(0, 96) || `worktree-${stamp}`;
}

export function parseWorktreeCommand(text: string): ParsedWorktreeCommand | null {
  const args = splitArgs(text).slice(1);
  const directory = args[0];
  if (!directory) return null;

  let name: string | undefined;
  let kind: SessionKind = "codex";
  const second = args[1];
  const third = args[2];

  if (second) {
    if (isValidKind(second)) {
      kind = second;
    } else {
      name = slugifySessionName(second);
      if (third && isValidKind(third)) kind = third;
    }
  }

  return { directory, name, kind };
}
