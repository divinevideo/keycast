import { describe, expect, test } from "bun:test";
import {
    emailMatchParts,
    emailSuggestionDiff,
    isShowingDidYouMean,
    isSuggestedUser,
    lookupResultsBanner,
    matchKindLabel,
    selectAutoExpandedPubkey,
    selectDisplayedUsers,
} from "./lookup-view";

interface Row {
    pubkey: string;
    authoritative: boolean;
    match_kind: "authoritative" | "partial" | "fuzzy";
}

const row = (
    pubkey: string,
    match_kind: Row["match_kind"] = "partial",
): Row => ({
    pubkey,
    authoritative: match_kind === "authoritative",
    match_kind,
});

describe("support admin user lookup view", () => {
    test("aligns a missing account character and describes the edit", () => {
        const diff = emailSuggestionDiff(
            "socialpublishllc@gmail.com",
            "socialpulishllc@gmail.com",
        );
        const gapIndex = diff.account.findIndex((part) => part.gap);

        expect(diff.distance).toBe(1);
        expect(diff.chip).toBe("1 letter off · missing 'b'");
        expect(gapIndex).toBeGreaterThan(-1);
        expect(diff.typed[gapIndex]).toEqual({ text: "b", changed: true, gap: false });
        expect(diff.account[gapIndex]).toEqual({ text: "", changed: true, gap: true });
    });

    test("describes a substituted account character", () => {
        const diff = emailSuggestionDiff("namea@example.com", "nameb@example.com");

        expect(diff.distance).toBe(1);
        expect(diff.chip).toBe("1 letter off · 'a'→'b'");
    });

    test("describes two edits and ignores email casing", () => {
        const diff = emailSuggestionDiff("Nameab@example.com", "namexy@example.com");

        expect(diff.distance).toBe(2);
        expect(diff.chip).toBe("2 letters off · 'a'→'x', 'b'→'y'");
    });

    test("marks a case-insensitive contains fragment inside an email", () => {
        expect(emailMatchParts("CreatorSocialPublishLLC@example.com", "socialp")).toEqual([
            { text: "Creator", matched: false },
            { text: "SocialP", matched: true },
            { text: "ublishLLC@example.com", matched: false },
        ]);
    });

    test("does not highlight exact emails or unrelated queries", () => {
        expect(emailMatchParts("account@example.com", "account@example.com")).toEqual([
            { text: "account@example.com", matched: false },
        ]);
        expect(emailMatchParts("account@example.com", "different")).toEqual([
            { text: "account@example.com", matched: false },
        ]);
    });

    test("combines result tiers, ranks them, and defensively deduplicates pubkeys", () => {
        const result = {
            results: [row("partial"), row("authoritative", "authoritative")],
            suggestions: [row("fuzzy", "fuzzy"), row("partial", "fuzzy")],
            total: 2,
            authoritative_match: true,
            authoritative_count: 1,
        };

        expect(selectDisplayedUsers(result)).toEqual([
            row("authoritative", "authoritative"),
            row("partial"),
            row("fuzzy", "fuzzy"),
        ]);
    });

    test("auto-expands a lone authoritative result", () => {
        const result = {
            results: [row("a", "authoritative")],
            suggestions: [],
            total: 1,
            authoritative_match: true,
            authoritative_count: 1,
        };

        expect(selectAutoExpandedPubkey(result)).toBe("a");
    });

    test("classifies partial and fuzzy rows with non-conflicting labels", () => {
        expect(matchKindLabel(row("authoritative", "authoritative"))).toBeNull();
        expect(matchKindLabel(row("partial"))).toBe("Partial match");
        expect(matchKindLabel(row("fuzzy", "fuzzy"))).toBe("Possible typo");
    });

    test("counts combined mixed rows in the results banner", () => {
        const result = {
            results: [row("partial")],
            suggestions: [row("fuzzy", "fuzzy")],
            total: 1,
            authoritative_match: false,
            authoritative_count: 0,
        };

        expect(lookupResultsBanner(result)).toBe("2 users found");
    });

    test("auto-expands one authoritative result ahead of loose candidates", () => {
        const result = {
            results: [row("authoritative", "authoritative"), row("loose")],
            suggestions: [],
            total: 2,
            authoritative_match: true,
            authoritative_count: 1,
        };

        expect(selectAutoExpandedPubkey(result)).toBe("authoritative");
        expect(isSuggestedUser(result.results[0])).toBe(false);
        expect(isSuggestedUser(result.results[1])).toBe(true);
    });

    test("marks a lone non-authoritative result as suggested without auto-expanding it", () => {
        const result = {
            results: [row("a")],
            suggestions: [],
            total: 1,
            authoritative_match: false,
            authoritative_count: 0,
        };

        expect(selectDisplayedUsers(result)).toEqual([row("a")]);
        expect(isSuggestedUser(result.results[0])).toBe(true);
        expect(isShowingDidYouMean(result, "partial")).toBe(false);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("falls back to fuzzy suggestions without auto-expanding them", () => {
        const result = {
            results: [],
            suggestions: [row("c", "fuzzy")],
            total: 0,
            authoritative_match: false,
            authoritative_count: 0,
        };

        expect(selectDisplayedUsers(result)).toEqual([row("c", "fuzzy")]);
        expect(isSuggestedUser(result.suggestions[0])).toBe(true);
        expect(isShowingDidYouMean(result, "typo@example.com")).toBe(true);
        expect(isShowingDidYouMean(result, "typo-fragment")).toBe(false);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("shows nothing and no suggestion banner when both are empty", () => {
        const result = {
            results: [],
            suggestions: [],
            total: 0,
            authoritative_match: false,
            authoritative_count: 0,
        };

        expect(selectDisplayedUsers(result)).toEqual([]);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("treats a null pre-search result as empty", () => {
        expect(selectDisplayedUsers(null)).toEqual([]);
        expect(selectAutoExpandedPubkey(null)).toBeNull();
    });
});
