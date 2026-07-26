import { describe, expect, it } from "vitest";
import { activeMentionQuery } from "@/components/team-sessions/ConversationComposer";

describe("activeMentionQuery", () => {
  it("returns the in-progress token at the caret", () => {
    const text = "hey @user-bo";
    expect(activeMentionQuery(text, text.length)).toBe("user-bo");
  });

  it("recognizes a mention at the very start", () => {
    expect(activeMentionQuery("@ada", 4)).toBe("ada");
  });

  it("returns null once the token is closed by whitespace", () => {
    const text = "hey @user-bob ";
    expect(activeMentionQuery(text, text.length)).toBeNull();
  });

  it("returns null when the caret is not in a mention", () => {
    expect(activeMentionQuery("plain text", 5)).toBeNull();
    expect(activeMentionQuery("email a@b.com", 13)).toBeNull();
  });

  it("only considers the token before the caret", () => {
    const text = "hi @bob and @cara";
    expect(activeMentionQuery(text, 6)).toBe("bo");
  });
});
