/** Pure selection helpers for the support-admin lookup view. */

export interface LookupResult<User> {
	results: User[];
	suggestions: User[];
	total: number;
	authoritative_match: boolean;
	authoritative_count: number;
}

export type LookupMatchKind = "authoritative" | "partial" | "fuzzy";

export interface EmailMatchPart {
	text: string;
	matched: boolean;
}

export interface EmailDiffPart {
	text: string;
	changed: boolean;
	gap: boolean;
}

export interface EmailSuggestionDiff {
	distance: number;
	chip: string;
	typed: EmailDiffPart[];
	account: EmailDiffPart[];
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

/** Align a typed email with a suggested account and describe their edits. */
export function emailSuggestionDiff(typedEmail: string, accountEmail: string): EmailSuggestionDiff {
	const typedCharacters = Array.from(typedEmail);
	const accountCharacters = Array.from(accountEmail);
	const columns = accountCharacters.length + 1;
	const distances = new Uint16Array((typedCharacters.length + 1) * columns);
	const distanceAt = (typedIndex: number, accountIndex: number): number =>
		distances[typedIndex * columns + accountIndex] ?? 0;
	const setDistance = (typedIndex: number, accountIndex: number, value: number): void => {
		distances[typedIndex * columns + accountIndex] = value;
	};

	for (let typedIndex = 0; typedIndex <= typedCharacters.length; typedIndex += 1) {
		setDistance(typedIndex, 0, typedIndex);
	}
	for (let accountIndex = 0; accountIndex <= accountCharacters.length; accountIndex += 1) {
		setDistance(0, accountIndex, accountIndex);
	}
	for (let typedIndex = 1; typedIndex <= typedCharacters.length; typedIndex += 1) {
		for (let accountIndex = 1; accountIndex <= accountCharacters.length; accountIndex += 1) {
			const substitutionCost =
				typedCharacters[typedIndex - 1]?.toLowerCase() ===
				accountCharacters[accountIndex - 1]?.toLowerCase()
					? 0
					: 1;
			setDistance(
				typedIndex,
				accountIndex,
				Math.min(
					distanceAt(typedIndex - 1, accountIndex) + 1,
					distanceAt(typedIndex, accountIndex - 1) + 1,
					distanceAt(typedIndex - 1, accountIndex - 1) + substitutionCost
				)
			);
		}
	}

	const typed: EmailDiffPart[] = [];
	const account: EmailDiffPart[] = [];
	const edits: string[] = [];
	let typedIndex = typedCharacters.length;
	let accountIndex = accountCharacters.length;

	while (typedIndex > 0 || accountIndex > 0) {
		const typedCharacter = typedCharacters[typedIndex - 1] ?? "";
		const accountCharacter = accountCharacters[accountIndex - 1] ?? "";
		if (
			typedIndex > 0 &&
			accountIndex > 0 &&
			typedCharacter.toLowerCase() === accountCharacter.toLowerCase() &&
			distanceAt(typedIndex, accountIndex) === distanceAt(typedIndex - 1, accountIndex - 1)
		) {
			typed.push({ text: typedCharacter, changed: false, gap: false });
			account.push({ text: accountCharacter, changed: false, gap: false });
			typedIndex -= 1;
			accountIndex -= 1;
		} else if (
			typedIndex > 0 &&
			accountIndex > 0 &&
			distanceAt(typedIndex, accountIndex) ===
				distanceAt(typedIndex - 1, accountIndex - 1) + 1
		) {
			typed.push({ text: typedCharacter, changed: true, gap: false });
			account.push({ text: accountCharacter, changed: true, gap: false });
			edits.push(`'${typedCharacter}'→'${accountCharacter}'`);
			typedIndex -= 1;
			accountIndex -= 1;
		} else if (
			typedIndex > 0 &&
			distanceAt(typedIndex, accountIndex) === distanceAt(typedIndex - 1, accountIndex) + 1
		) {
			typed.push({ text: typedCharacter, changed: true, gap: false });
			account.push({ text: "", changed: true, gap: true });
			edits.push(`missing '${typedCharacter}'`);
			typedIndex -= 1;
		} else {
			typed.push({ text: "", changed: true, gap: true });
			account.push({ text: accountCharacter, changed: true, gap: false });
			edits.push(`extra '${accountCharacter}'`);
			accountIndex -= 1;
		}
	}

	typed.reverse();
	account.reverse();
	edits.reverse();
	const distance = distanceAt(typedCharacters.length, accountCharacters.length);
	const label = `${distance} ${distance === 1 ? "letter" : "letters"} off`;
	const detail = distance > 0 && distance <= 2 ? ` · ${edits.join(", ")}` : "";

	return { distance, chip: `${label}${detail}`, typed, account };
}

/** Combine lookup tiers in rank order and defensively de-duplicate by pubkey. */
export function selectDisplayedUsers<
	User extends { pubkey: string; match_kind: LookupMatchKind },
>(result: LookupResult<User> | null): User[] {
	if (!result) return [];
	const rank: Record<LookupMatchKind, number> = {
		authoritative: 0,
		partial: 1,
		fuzzy: 2
	};
	const seen = new Set<string>();

	return [...result.results, ...result.suggestions]
		.map((user, index) => ({ user, index }))
		.sort((left, right) => rank[left.user.match_kind] - rank[right.user.match_kind] || left.index - right.index)
		.map(({ user }) => user)
		.filter((user) => {
			if (seen.has(user.pubkey)) return false;
			seen.add(user.pubkey);
			return true;
		});
}

/** Select the user-facing provenance label for one lookup row. */
export function matchKindLabel(user: { match_kind: LookupMatchKind }): string | null {
	if (user.match_kind === "partial") return "Partial match";
	if (user.match_kind === "fuzzy") return "Possible typo";
	return null;
}

/** Report whether one lookup row is a loose or fuzzy suggestion. */
export function isSuggestedUser(user: { match_kind: LookupMatchKind }): boolean {
	return user.match_kind !== "authoritative";
}

/** Report whether the displayed rows came from the fuzzy suggestion fallback. */
export function isShowingDidYouMean<User extends { match_kind: LookupMatchKind }>(
	result: LookupResult<User> | null,
	query: string
): boolean {
	return (
		result !== null &&
		query.trim().includes("@") &&
		!result.authoritative_match &&
		result.results.length === 0 &&
		result.suggestions.length > 0 &&
		result.suggestions.every((user) => user.match_kind === "fuzzy")
	);
}

/** Select banner copy using the combined, de-duplicated row count. */
export function lookupResultsBanner<
	User extends { pubkey: string; match_kind: LookupMatchKind },
>(result: LookupResult<User> | null): string | null {
	if (!result) return null;
	if (result.total >= 20) return "Showing first 20 of many results — refine your search";
	const displayedCount = selectDisplayedUsers(result).length;
	return displayedCount > 1 ? `${displayedCount} users found` : null;
}

/** Select a lone authoritative result for automatic expansion. */
export function selectAutoExpandedPubkey<User extends { pubkey: string }>(
	result: LookupResult<User> | null
): string | null {
	if (!result?.authoritative_match || result.authoritative_count !== 1) return null;
	return result.results[0]?.pubkey ?? null;
}
