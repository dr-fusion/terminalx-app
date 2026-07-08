/**
 * Detects an interactive selection prompt — a Claude Code / Codex "pick an
 * option" menu — in a terminal pane.
 *
 * These menus live only in the TUI. Claude Code does not write an
 * AskUserQuestion tool_use to its JSONL transcript until *after* the user
 * answers, so chat mode (which otherwise streams the JSONL) would never tell
 * the user that a decision is blocking the session. We read the prompt off the
 * live, ANSI-stripped pane instead.
 *
 * The function is deliberately conservative: it only reports a prompt when the
 * bottom of the screen holds a 1..N numbered menu with an active-selection
 * cursor (❯). A plain numbered list in normal output has no cursor and is
 * ignored, so we don't spam the chat with false positives.
 */

// "❯ 1. Yes", "  2. No", "› 3. Maybe" — a numbered, optionally-cursored choice.
const OPTION_RE = /^\s*(?:[❯›▶▸]\s*)?(\d{1,2})[.)]\s+(\S.*?)\s*$/u;
// Active-selection cursor. Its presence is what separates a live menu from a
// plain numbered list printed in normal output.
const CURSOR_RE = /[❯›▶▸]/u;
// A horizontal rule / box edge Claude draws above a question block.
const SEPARATOR_RE = /^[\s│]*[─━—–_=]{6,}[\s│]*$/u;
const CLAUDE_RATING_QUESTION_RE = /How is Claude doing this session\?\s*\(optional\)/iu;
const CLAUDE_RATING_OPTIONS_RE = /\b1:\s*Bad\b.*\b2:\s*Fine\b.*\b3:\s*Good\b.*\b0:\s*Dismiss\b/iu;
const CLAUDE_CONSENT_QUESTION_RE =
  /Can Anthropic look at your session transcript to help us improve Claude Code\?/iu;
const CLAUDE_CONSENT_OPTIONS_RE = /\by:\s*Yes\b.*\bn:\s*No\b.*\bd:\s*Don.t ask again\b/iu;
const FOOTER_RE = /^(?:Press\s+enter\s+to\s+confirm\b|Use\s+.+\bto\s+(?:navigate|select)\b)/iu;

const MAX_CONTEXT_LINES = 14;
const SEPARATOR_LOOKBACK = 18;

export interface SelectionPrompt {
  /** Stable while the user moves the cursor; changes when the menu changes. */
  signature: string;
  /** Ready-to-send plain-text message. */
  text: string;
}

export function extractSelectionPrompt(paneText: string): SelectionPrompt | null {
  const lines = paneText
    .replace(/\r/g, "")
    .split("\n")
    .map((l) => l.replace(/\s+$/u, ""));

  // Ignore trailing blank lines off the bottom of the pane.
  let end = lines.length - 1;
  while (end >= 0 && lines[end]!.trim() === "") end--;
  if (end < 0) return null;

  while (end >= 0 && isPromptFooter(lines[end]!)) {
    end--;
    while (end >= 0 && lines[end]!.trim() === "") end--;
  }
  if (end < 0) return null;

  const inlineRating = extractInlineRatingPrompt(lines, end);
  if (inlineRating) return inlineRating;

  const inlineConsent = extractInlineConsentPrompt(lines, end);
  if (inlineConsent) return inlineConsent;

  // Walk up from the bottom collecting the contiguous run of option lines.
  const options: { num: number; label: string }[] = [];
  let cursorSeen = false;
  let menuTop = end + 1;
  for (let i = end; i >= 0; i--) {
    const line = lines[i]!;
    if (line.trim() === "") {
      if (options.length > 0) break; // a blank above the menu ends it
      continue;
    }
    const m = line.match(OPTION_RE);
    if (m) {
      if (CURSOR_RE.test(line)) cursorSeen = true;
      options.unshift({ num: Number(m[1]), label: m[2]!.trim() });
      menuTop = i;
      continue;
    }
    break; // non-option, non-blank line: top of the menu block
  }

  if (options.length < 2 || !cursorSeen) return null;
  // Require a clean 1..N sequence so prose like "... in v2. foo" can't match.
  if (!options.every((o, idx) => o.num === idx + 1)) return null;

  const context = gatherContext(lines, menuTop);
  const optionText = options.map((o) => `${o.num}. ${o.label}`).join("\n");
  const body = [context.join("\n"), optionText].filter(Boolean).join("\n\n");

  const text =
    `📋 Waiting for your answer:\n\n${body}\n\n` +
    `Reply with the option number (e.g. 1), or /view screen for tap-to-choose buttons.`;
  const signature = hash(
    context.join("\n") + "\0" + options.map((o) => `${o.num}:${o.label}`).join("\0")
  );
  return { signature, text };
}

function extractInlineRatingPrompt(lines: string[], end: number): SelectionPrompt | null {
  const start = Math.max(0, end - 8);
  for (let i = start; i <= end; i++) {
    const question = cleanLine(lines[i] ?? "");
    if (!CLAUDE_RATING_QUESTION_RE.test(question)) continue;
    for (let j = i + 1; j <= Math.min(end, i + 3); j++) {
      const options = cleanLine(lines[j] ?? "");
      if (!CLAUDE_RATING_OPTIONS_RE.test(options)) continue;
      const optionText = "1. Bad\n2. Fine\n3. Good\n0. Dismiss";
      return {
        signature: hash(`claude-rating\0${question}\0${options}`),
        text:
          `📋 Waiting for your answer:\n\n${question}\n\n${optionText}\n\n` +
          "Reply with 0, 1, 2, or 3, or /view screen for the live prompt.",
      };
    }
  }
  return null;
}

function extractInlineConsentPrompt(lines: string[], end: number): SelectionPrompt | null {
  const start = Math.max(0, end - 10);
  for (let i = start; i <= end; i++) {
    const question = cleanLine(lines[i] ?? "");
    if (!CLAUDE_CONSENT_QUESTION_RE.test(question)) continue;
    for (let j = i + 1; j <= Math.min(end, i + 5); j++) {
      const options = cleanLine(lines[j] ?? "");
      if (!CLAUDE_CONSENT_OPTIONS_RE.test(options)) continue;
      const optionText = "y. Yes\nn. No\nd. Don't ask again";
      return {
        signature: hash("claude-consent\0" + question + "\0" + options),
        text:
          "📋 Waiting for your answer:\n\n" +
          question +
          "\n\n" +
          optionText +
          "\n\nReply with y, n, or d, or /view screen for the live prompt.",
      };
    }
  }
  return null;
}

/**
 * Collect the question / context lines above the menu. Prefer a separator (or
 * box rule) as the top boundary — Claude's multi-question review screen has
 * blank lines inside the block — and otherwise take the tight run of non-blank
 * lines directly above the menu (a permission prompt's question).
 */
function gatherContext(lines: string[], menuTop: number): string[] {
  let sepIdx = -1;
  for (let j = menuTop - 1; j >= 0 && menuTop - j <= SEPARATOR_LOOKBACK; j--) {
    if (SEPARATOR_RE.test(lines[j]!)) {
      sepIdx = j;
      break;
    }
  }

  const out: string[] = [];
  if (sepIdx >= 0) {
    for (let j = sepIdx + 1; j < menuTop && out.length < MAX_CONTEXT_LINES; j++) {
      if (SEPARATOR_RE.test(lines[j]!)) continue;
      const t = cleanLine(lines[j]!);
      if (t) out.push(t);
    }
    return out;
  }

  for (let j = menuTop - 1; j >= 0 && out.length < MAX_CONTEXT_LINES; j--) {
    if (lines[j]!.trim() === "") break;
    if (SEPARATOR_RE.test(lines[j]!)) break;
    const t = cleanLine(lines[j]!);
    if (t) out.unshift(t);
  }
  return out;
}

/** Trim the ← / → navigation arrows Claude draws around the progress bar. */
function cleanLine(line: string): string {
  return line
    .replace(/^[\s←]+/u, "")
    .replace(/[\s→]+$/u, "")
    .trim();
}

function isPromptFooter(line: string): boolean {
  return FOOTER_RE.test(cleanLine(line));
}

function hash(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16);
}
