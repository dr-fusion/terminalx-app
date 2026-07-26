import { describe, expect, it } from "vitest";
import { MOBILE_NAV_ITEMS, isMobileNavItemActive } from "@/components/layout/MobileNav";
import { linesToList } from "@/components/team-sessions/OfferHandoffDialog";
import { highlightSegments } from "@/components/team-sessions/ConversationSearch";

describe("mobile navigation model", () => {
  it("covers the primary app destinations", () => {
    const hrefs = MOBILE_NAV_ITEMS.map((item) => item.href);
    expect(hrefs).toEqual(
      expect.arrayContaining([
        "/dashboard",
        "/team-sessions",
        "/inbox",
        "/playground",
        "/replay",
        "/settings",
      ])
    );
  });

  it("marks the exact route and its subroutes active", () => {
    expect(isMobileNavItemActive("/team-sessions", "/team-sessions")).toBe(true);
    expect(isMobileNavItemActive("/team-sessions", "/team-sessions/abc")).toBe(true);
    expect(isMobileNavItemActive("/inbox", "/inbox")).toBe(true);
  });

  it("does not treat a prefix collision as active", () => {
    expect(isMobileNavItemActive("/replay", "/replays-archive")).toBe(false);
    expect(isMobileNavItemActive("/settings", "/dashboard")).toBe(false);
  });
});

describe("handoff briefing list parsing", () => {
  it("splits one item per non-empty trimmed line", () => {
    expect(linesToList("  first \n\n second\n")).toEqual(["first", "second"]);
  });

  it("returns an empty list for blank input", () => {
    expect(linesToList("   \n  \n")).toEqual([]);
  });
});

describe("conversation search highlight", () => {
  it("splits a body into matched and unmatched segments (case-insensitive)", () => {
    const segments = highlightSegments("Deploy the Deploy step", "deploy");
    expect(segments.filter((s) => s.match).map((s) => s.text)).toEqual(["Deploy", "Deploy"]);
    expect(segments.map((s) => s.text).join("")).toBe("Deploy the Deploy step");
  });

  it("returns the whole body unmatched when the needle is absent", () => {
    expect(highlightSegments("nothing here", "xyz")).toEqual([
      { text: "nothing here", match: false },
    ]);
  });

  it("treats an empty needle as no highlight", () => {
    expect(highlightSegments("body", "  ")).toEqual([{ text: "body", match: false }]);
  });
});
