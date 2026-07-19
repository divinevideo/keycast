/** Pure selection helpers for the support-admin lookup view. */

export interface LookupResult<User> {
	results: User[];
	suggestions: User[];
	total: number;
}

/** Select authoritative rows, falling back to fuzzy suggestions only when needed. */
export function selectDisplayedUsers<User>(result: LookupResult<User> | null): User[] {
	if (!result) return [];
	return result.results.length > 0 ? result.results : result.suggestions;
}

/** Report whether the displayed rows are fuzzy suggestions. */
export function isShowingSuggestions<User>(result: LookupResult<User> | null): boolean {
	return result !== null && result.results.length === 0 && result.suggestions.length > 0;
}

/** Select a lone authoritative result for automatic expansion. */
export function selectAutoExpandedPubkey<User extends { pubkey: string }>(
	result: LookupResult<User> | null
): string | null {
	if (!result || result.results.length !== 1) return null;
	return result.results[0]?.pubkey ?? null;
}
