/** Pure selection helpers for the support-admin lookup view. */

export interface LookupResult<User> {
	results: User[];
	suggestions: User[];
	total: number;
	authoritative_match: boolean;
}

export interface EmailMatchPart {
	text: string;
	matched: boolean;
}

/** Split a contains-result email into plain and matched text parts. */
export function emailMatchParts(email: string, query: string): EmailMatchPart[] {
	const fragment = query.trim();
	const normalizedEmail = email.toLowerCase();
	const normalizedFragment = fragment.toLowerCase();

	if (!normalizedFragment || normalizedEmail === normalizedFragment) {
		return [{ text: email, matched: false }];
	}

	const parts: EmailMatchPart[] = [];
	let offset = 0;
	let matchOffset = normalizedEmail.indexOf(normalizedFragment);

	while (matchOffset !== -1) {
		if (matchOffset > offset) {
			parts.push({ text: email.slice(offset, matchOffset), matched: false });
		}
		const matchEnd = matchOffset + fragment.length;
		parts.push({ text: email.slice(matchOffset, matchEnd), matched: true });
		offset = matchEnd;
		matchOffset = normalizedEmail.indexOf(normalizedFragment, offset);
	}

	if (parts.length === 0) {
		return [{ text: email, matched: false }];
	}
	if (offset < email.length) {
		parts.push({ text: email.slice(offset), matched: false });
	}
	return parts;
}

/** Select primary lookup rows, falling back to fuzzy suggestions only when needed. */
export function selectDisplayedUsers<User>(result: LookupResult<User> | null): User[] {
	if (!result) return [];
	return result.results.length > 0 ? result.results : result.suggestions;
}

/** Report whether the displayed rows are unconfirmed suggestions. */
export function isShowingSuggestions<User>(result: LookupResult<User> | null): boolean {
	return result !== null && !result.authoritative_match && selectDisplayedUsers(result).length > 0;
}

/** Select a lone authoritative result for automatic expansion. */
export function selectAutoExpandedPubkey<User extends { pubkey: string }>(
	result: LookupResult<User> | null
): string | null {
	if (!result?.authoritative_match || result.results.length !== 1) return null;
	return result.results[0]?.pubkey ?? null;
}
