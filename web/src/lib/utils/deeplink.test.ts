import { describe, expect, test } from "bun:test";
import { deeplinkQuery } from "./deeplink";

describe("deeplinkQuery", () => {
    test("returns the q value when present", () => {
        expect(deeplinkQuery(new URLSearchParams("q=npub1abc"))).toBe(
            "npub1abc",
        );
    });

    test("trims surrounding whitespace", () => {
        expect(deeplinkQuery(new URLSearchParams("q=%20%20kofi%20%20"))).toBe(
            "kofi",
        );
    });

    test("keeps internal whitespace, trimming only the ends", () => {
        expect(deeplinkQuery(new URLSearchParams("q=%20foo%20bar%20"))).toBe(
            "foo bar",
        );
    });

    test("returns null when q is absent", () => {
        expect(deeplinkQuery(new URLSearchParams(""))).toBeNull();
    });

    test("returns null when q is empty", () => {
        expect(deeplinkQuery(new URLSearchParams("q="))).toBeNull();
    });

    test("returns null when q is whitespace only", () => {
        expect(deeplinkQuery(new URLSearchParams("q=%20%20"))).toBeNull();
    });
});
