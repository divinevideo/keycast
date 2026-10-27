import { expect, test } from "bun:test";
import { AVAILABLE_PERMISSIONS, TEAM_POLICY_PERMISSIONS } from "../types";

test("team creation holds challenge permission while enforcement remains registered", () => {
    expect(AVAILABLE_PERMISSIONS).toContain("challenge_actions");
    expect(TEAM_POLICY_PERMISSIONS).not.toContain("challenge_actions");
    for (const identifier of ["allowed_kinds", "content_filter", "encrypt_to_self"]) {
        expect(TEAM_POLICY_PERMISSIONS).toContain(identifier);
    }
});
