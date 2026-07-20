import { describe, expect, test } from "bun:test";
import {
    emailMatchParts,
    isShowingSuggestions,
    selectAutoExpandedPubkey,
    selectDisplayedUsers,
} from "./lookup-view";

interface Row {
    pubkey: string;
}

const row = (pubkey: string): Row => ({ pubkey });

describe("support admin user lookup view", () => {
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
        };

        expect(selectAutoExpandedPubkey(result)).toBe("a");
    });

    test("marks a lone non-authoritative result as suggested without auto-expanding it", () => {
        const result = {
            results: [row("a")],
            suggestions: [],
            total: 1,
            authoritative_match: false,
        };

        expect(selectDisplayedUsers(result)).toEqual([row("a")]);
        expect(isShowingSuggestions(result)).toBe(true);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("falls back to fuzzy suggestions without auto-expanding them", () => {
        const result = {
            results: [],
            suggestions: [row("c")],
            total: 0,
            authoritative_match: false,
        };

        expect(selectDisplayedUsers(result)).toEqual([row("c")]);
        expect(isShowingSuggestions(result)).toBe(true);
        expect(selectAutoExpandedPubkey(result)).toBeNull();
    });

    test("shows nothing and no suggestion banner when both are empty", () => {
        const result = { results: [], suggestions: [], total: 0, authoritative_match: false };

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
