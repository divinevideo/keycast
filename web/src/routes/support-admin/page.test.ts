import { describe, expect, test } from "bun:test";

const pageSource = await Bun.file(
    new URL("./+page.svelte", import.meta.url),
).text();

describe("support admin user lookup", () => {
    test("renders fuzzy email suggestions with specific search guidance", () => {
        expect(pageSource).toContain("suggestions: UserDetails[]");
        expect(pageSource).toContain("searchResult.suggestions");
        expect(pageSource).toContain("Did you mean?");
        expect(pageSource).toContain(
            'placeholder="Email, username, Vine ID, or pubkey"',
        );
        expect(pageSource).toContain(
            "Full or partial email, username, Vine ID, hex pubkey, or npub",
        );
    });
});
