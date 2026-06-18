import { describe, expect, test } from "bun:test";
import { safeRedirectPath } from "./redirect";

describe("safeRedirectPath", () => {
    test("allows same-origin absolute paths and preserves query/hash", () => {
        expect(safeRedirectPath("/support-admin")).toBe("/support-admin");
        expect(safeRedirectPath("/admin/registered-clients?x=1#y")).toBe(
            "/admin/registered-clients?x=1#y",
        );
    });

    test("falls back to / for missing or relative values", () => {
        expect(safeRedirectPath(null)).toBe("/");
        expect(safeRedirectPath(undefined)).toBe("/");
        expect(safeRedirectPath("")).toBe("/");
        expect(safeRedirectPath("support-admin")).toBe("/");
    });

    test("rejects absolute off-origin URLs", () => {
        expect(safeRedirectPath("https://evil.com")).toBe("/");
        expect(safeRedirectPath("http://evil.com/path")).toBe("/");
    });

    test("rejects protocol-relative and backslash open-redirect vectors", () => {
        expect(safeRedirectPath("//evil.com")).toBe("/");
        expect(safeRedirectPath("/\\evil.com")).toBe("/");
        expect(safeRedirectPath("/\\/evil.com")).toBe("/");
    });
});
