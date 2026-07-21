import { describe, expect, test } from "bun:test";
import {
    emailMatchParts,
    emailSuggestionDiff,
    isShowingDidYouMean,
    isShowingSuggestions,
    selectAutoExpandedPubkey,
    selectDisplayedUsers,
} from "./lookup-view";

interface Row {
    pubkey: string;
}

const row = (pubkey: string): Row => ({ pubkey });

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

    test("shows authoritative results and hides suggestions when results exist", () => {
        const result = {
            results: [row("a"), row("b")],
            suggestions: [row("c")],
            total: 2,
            authoritative_match: true,
            authoritative_count: 2,
        };

        expect(selectDisplayedUsers(result)).toEqual([row("a"), row("b")]);
        expect(isShowingSuggestions(result)).toBe(false);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("auto-expands a lone authoritative result", () => {
        const result = {
            results: [row("a")],
            suggestions: [],
            total: 1,
            authoritative_match: true,
            authoritative_count: 1,
        };

        expect(selectAutoExpandedPubkey(result)).toBe("a");
    });

    test("auto-expands one authoritative result ahead of loose candidates", () => {
        const result = {
            results: [row("authoritative"), row("loose")],
            suggestions: [],
            total: 2,
            authoritative_match: true,
            authoritative_count: 1,
        };

        expect(selectAutoExpandedPubkey(result)).toBe("authoritative");
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
        expect(isShowingSuggestions(result)).toBe(true);
        expect(isShowingDidYouMean(result)).toBe(false);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("falls back to fuzzy suggestions without auto-expanding them", () => {
        const result = {
            results: [],
            suggestions: [row("c")],
            total: 0,
            authoritative_match: false,
            authoritative_count: 0,
        };

        expect(selectDisplayedUsers(result)).toEqual([row("c")]);
        expect(isShowingSuggestions(result)).toBe(true);
        expect(isShowingDidYouMean(result)).toBe(true);
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
        expect(isShowingSuggestions(result)).toBe(false);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("treats a null pre-search result as empty", () => {
        expect(selectDisplayedUsers(null)).toEqual([]);
        expect(isShowingSuggestions(null)).toBe(false);
        expect(selectAutoExpandedPubkey(null)).toBeNull();
    });
});
