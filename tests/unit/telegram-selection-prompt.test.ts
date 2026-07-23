import { describe, it, expect } from "vitest";
import { extractSelectionPrompt } from "@/lib/telegram/selection-prompt";

// A Claude Code AskUserQuestion multi-question "review" screen (captured live).
const REVIEW_SCREEN = `
${"─".repeat(80)}
←  ☒ Leverage fix  ☒ Post-Only  ✔ Submit  →

Review your answers

 ● How should we fix the leverage size@oracle vs admit@fill mismatch (fund-critical)?
   → Oracle-deviation band on fills
 ● Add Post-Only to the perp router now?
   → Defer

Ready to submit your answers?

❯ 1. Submit answers
  2. Cancel



`;

// A plain Claude Code permission prompt.
const PERMISSION_SCREEN = `Some earlier assistant output here.

Do you want to make this edit to PerpsTradeForm.tsx?
❯ 1. Yes
  2. No, and tell Claude what to do differently`;

describe("extractSelectionPrompt", () => {
  it("extracts the question block and options from a review screen", () => {
    const prompt = extractSelectionPrompt(REVIEW_SCREEN);
    expect(prompt).not.toBeNull();
    expect(prompt!.text).toContain("1. Submit answers");
    expect(prompt!.text).toContain("2. Cancel");
    expect(prompt!.text).toContain("Ready to submit your answers?");
    expect(prompt!.text).toContain("How should we fix the leverage");
    // The trailing nav arrows around the progress bar are trimmed.
    expect(prompt!.text).not.toContain("←");
    expect(prompt!.text).not.toContain("→  ");
  });

  it("extracts a permission prompt and stops at the blank above the question", () => {
    const prompt = extractSelectionPrompt(PERMISSION_SCREEN);
    expect(prompt).not.toBeNull();
    expect(prompt!.text).toContain("Do you want to make this edit to PerpsTradeForm.tsx?");
    expect(prompt!.text).toContain("1. Yes");
    expect(prompt!.text).toContain("2. No, and tell Claude what to do differently");
    // Earlier output above the blank line must not leak in.
    expect(prompt!.text).not.toContain("Some earlier assistant output");
  });

  it("extracts Codex approval prompts with an instruction footer below the options", () => {
    const prompt = extractSelectionPrompt(`
◦ Running npm run dev:admin

${"─".repeat(80)}

  Would you like to run the following command?

  Environment: local

  Reason: Allow starting the admin Next.js dev server on port 3002 so I can capture board-deck screenshots.

  $ npm run dev:admin

› 1. Yes, proceed (y)
  2. Yes, and don't ask again for commands that start with \`npm run dev:admin\` (p)
  3. No, and tell Codex what to do differently (esc)

  Press enter to confirm or esc to cancel

`);

    expect(prompt).not.toBeNull();
    expect(prompt!.text).toContain("Would you like to run the following command?");
    expect(prompt!.text).toContain("$ npm run dev:admin");
    expect(prompt!.text).toContain("1. Yes, proceed (y)");
    expect(prompt!.text).toContain("3. No, and tell Codex what to do differently");
    expect(prompt!.text).not.toContain("Press enter to confirm");
  });

  it("extracts Claude inline session rating prompts", () => {
    const prompt = extractSelectionPrompt(`
Some Claude output

● How is Claude doing this session? (optional)
  1: Bad    2: Fine   3: Good   0: Dismiss

`);

    expect(prompt).not.toBeNull();
    expect(prompt!.text).toContain("How is Claude doing this session?");
    expect(prompt!.text).toContain("1. Bad");
    expect(prompt!.text).toContain("0. Dismiss");
  });

  it("extracts Claude transcript consent prompts", () => {
    const prompt = extractSelectionPrompt(`
● Can Anthropic look at your session transcript to help us improve Claude Code?
  y: Yes    n: No     d: Don't ask again

`);

    expect(prompt).not.toBeNull();
    expect(prompt!.text).toContain("Can Anthropic look at your session transcript");
    expect(prompt!.text).toContain("y. Yes");
    expect(prompt!.text).toContain("d. Don't ask again");
  });

  it("ignores a plain numbered list with no selection cursor", () => {
    const prose = `Here is the plan:
1. First do this
2. Then do that
3. Finally this`;
    expect(extractSelectionPrompt(prose)).toBeNull();
  });

  it("ignores a menu with only one option", () => {
    expect(extractSelectionPrompt("Pick:\n❯ 1. Only choice")).toBeNull();
  });

  it("ignores an empty pane", () => {
    expect(extractSelectionPrompt("\n\n  \n")).toBeNull();
  });

  it("keeps the same signature as the cursor moves between options", () => {
    const onFirst = "Proceed?\n❯ 1. Yes\n  2. No";
    const onSecond = "Proceed?\n  1. Yes\n❯ 2. No";
    const a = extractSelectionPrompt(onFirst);
    const b = extractSelectionPrompt(onSecond);
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(a!.signature).toBe(b!.signature);
  });

  it("changes signature when the question or options change", () => {
    const one = extractSelectionPrompt("Proceed?\n❯ 1. Yes\n  2. No");
    const two = extractSelectionPrompt("Delete it?\n❯ 1. Yes\n  2. No");
    expect(one!.signature).not.toBe(two!.signature);
  });
});
