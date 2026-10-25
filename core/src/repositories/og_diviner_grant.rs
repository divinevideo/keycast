// ABOUTME: Loads the closed OG Diviner grant roster into og_diviner_grants
// ABOUTME: Validates and counts a private pubkey list without ever echoing it

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use sqlx::PgPool;

use crate::repositories::RepositoryError;

/// How many offending line numbers a roster error names. The count is always
/// exact; the list is only a starting point for fixing the file.
const REPORTED_LINE_LIMIT: usize = 10;

/// The rule that admitted a pubkey to the grant roster.
///
/// Mirrors the `evidence` CHECK constraint in the
/// `20261023120000_add_og_diviner_grants` migration. A new variant needs a
/// migration that widens that constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OgDivinerGrantEvidence {
    /// Published an original video through a Divine app, which the relay
    /// recorded receiving before the cutoff (keycast#440).
    PreCutoffAppPost,
}

impl OgDivinerGrantEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreCutoffAppPost => "pre_cutoff_app_post",
        }
    }
}

impl FromStr for OgDivinerGrantEvidence {
    type Err = String;

    fn from_str(label: &str) -> Result<Self, Self::Err> {
        match label {
            "pre_cutoff_app_post" => Ok(Self::PreCutoffAppPost),
            _ => Err("unknown OG Diviner grant evidence label".to_string()),
        }
    }
}

/// A validated grant roster: unique pubkeys in first-seen order.
///
/// `Debug` reports counts only, so logging or panicking with a roster in scope
/// cannot leak the cohort.
#[derive(Clone, PartialEq, Eq)]
pub struct GrantRoster {
    entries: usize,
    pubkeys: Vec<String>,
}

impl GrantRoster {
    /// Non-blank lines read, duplicates included.
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Crate-private so callers outside the loader cannot print the cohort.
    pub(crate) fn pubkeys(&self) -> &[String] {
        &self.pubkeys
    }

    /// Lines that repeated a pubkey already seen earlier in the roster.
    pub fn duplicates(&self) -> usize {
        self.entries - self.pubkeys.len()
    }
}

impl fmt::Debug for GrantRoster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRoster")
            .field("entries", &self.entries)
            .field("unique", &self.pubkeys.len())
            .finish()
    }
}

/// Why a roster was rejected. Messages name line numbers, never contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantRosterError {
    #[error(
        "{count} line(s) are not 64-character lowercase hex pubkeys; first at line(s) {}",
        join_line_numbers(.first)
    )]
    InvalidLines { count: usize, first: Vec<usize> },
    #[error("the roster contains no pubkeys")]
    Empty,
}

fn join_line_numbers(lines: &[usize]) -> String {
    lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_lowercase_hex_pubkey(candidate: &str) -> bool {
    candidate.len() == 64
        && candidate
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses a roster of one pubkey per line.
///
/// Blank lines and whitespace around a pubkey are ignored. Anything else must
/// be a 64-character lowercase hex pubkey: npubs, uppercase hex, and stray
/// bytes such as a byte-order mark are rejected rather than normalised, since
/// they mean the roster came from a pipeline other than the one reviewed. A
/// single bad line rejects the whole roster, so nothing is loaded from it.
pub fn parse_grant_roster(input: &str) -> Result<GrantRoster, GrantRosterError> {
    let mut entries = 0;
    let mut seen = HashSet::new();
    let mut pubkeys = Vec::new();
    let mut invalid_count = 0;
    let mut invalid_first = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let candidate = line.trim();
        if candidate.is_empty() {
            continue;
        }
        entries += 1;
        if !is_lowercase_hex_pubkey(candidate) {
            invalid_count += 1;
            if invalid_first.len() < REPORTED_LINE_LIMIT {
                invalid_first.push(index + 1);
            }
            continue;
        }
        if seen.insert(candidate) {
            pubkeys.push(candidate.to_string());
        }
    }

    if invalid_count > 0 {
        return Err(GrantRosterError::InvalidLines {
            count: invalid_count,
            first: invalid_first,
        });
    }
    if entries == 0 {
        return Err(GrantRosterError::Empty);
    }
    Ok(GrantRoster { entries, pubkeys })
}

/// What a load did, or would do on a dry run. Counts and the target tenant
/// only, so an operator can confirm the tenant before applying.
///
/// Every unique roster pubkey lands in exactly one of `newly_granted`,
/// `already_granted` and `excluded_deleted`, so the three sum to `unique`. A
/// pubkey with a recorded deletion in the tenant is `excluded_deleted` whether
/// or not it already had a grant; if it did, the load removes that grant and
/// also counts it in `revoked_deleted`. A dry run reports the same counts the
/// load would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLoadReport {
    pub tenant_domain: String,
    pub tenant_name: String,
    pub unique: usize,
    pub newly_granted: u64,
    pub already_granted: u64,
    /// Roster pubkeys with a `service_account_deletions` row in this tenant.
    pub excluded_deleted: u64,
    /// Of `excluded_deleted`, those whose existing grant the load removed.
    pub revoked_deleted: u64,
    pub applied: bool,
}

/// Repository for the OG Diviner grant roster.
///
/// No method holds a connection while acquiring another, so it works on the
/// loader's one-connection pool.
#[derive(Debug)]
pub struct OgDivinerGrantRepository {
    pool: PgPool,
}

impl OgDivinerGrantRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Grants every pubkey in `roster` in `tenant_id`, or with `apply` false,
    /// reports what that would do without writing.
    ///
    /// A pubkey whose account deletion is recorded in the tenant is never
    /// granted, and loses any grant it has: the coordinator will not call
    /// Keycast for that deletion again, so nothing else would remove it. Those
    /// records can be compacted 30 days after the deletion, which is why the
    /// roster has to be built right before it is loaded (see docs/DEPLOYMENT.md).
    ///
    /// Re-running a roster grants nothing new: an existing grant keeps its
    /// original evidence and timestamp and is counted as already granted. An
    /// applied load is one transaction, so it lands whole or not at all, and
    /// every row it writes shares one `created_at`.
    pub async fn load(
        &self,
        tenant_id: i64,
        evidence: OgDivinerGrantEvidence,
        roster: &GrantRoster,
        apply: bool,
    ) -> Result<GrantLoadReport, RepositoryError> {
        // Checked explicitly so a dry run against the wrong tenant fails the
        // same way the real load would, instead of reporting a clean result.
        let tenant: Option<(String, String)> =
            sqlx::query_as("SELECT domain, name FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some((tenant_domain, tenant_name)) = tenant else {
            return Err(RepositoryError::NotFound(format!("tenant {tenant_id}")));
        };

        let unique = roster.pubkeys().len() as u64;
        let (newly_granted, already_granted, excluded_deleted, revoked_deleted) = if apply {
            // No lock against account deletion, by choice: this runs once, and
            // a lock would make every deletion in the tenant wait on it. The
            // cost is a narrow race. A deletion that commits while this
            // statement runs can miss the grant it inserts, leaving a grant on
            // a deleted account. The runbook removes those afterwards with a
            // cleanup that only revokes (see docs/DEPLOYMENT.md), rather than by
            // re-applying, which would also re-grant anyone whose grant was
            // removed since by a deletion that left no record.
            //
            // One statement, so it sends the roster once and its parts share
            // one snapshot of the deletion records, which is what makes the
            // counts partition the roster. A pubkey with a recorded deletion
            // is never inserted, and loses a grant it already had: it is
            // reported as excluded, so it must also end up without one. The
            // insert and the delete touch disjoint pubkeys.
            let mut tx = self.pool.begin().await?;
            let (newly_granted, revoked_deleted, excluded_deleted): (i64, i64, i64) =
                sqlx::query_as(
                    "WITH roster AS (
                         SELECT unnest($2::text[]) AS pubkey
                     ), deleted AS (
                         SELECT r.pubkey FROM roster r
                         WHERE EXISTS (
                             SELECT 1 FROM service_account_deletions d
                             WHERE d.tenant_id = $1 AND d.user_pubkey = r.pubkey
                         )
                     ), inserted AS (
                         INSERT INTO og_diviner_grants (tenant_id, pubkey, evidence)
                         SELECT $1, r.pubkey, $3 FROM roster r
                         WHERE NOT EXISTS (SELECT 1 FROM deleted x WHERE x.pubkey = r.pubkey)
                         ON CONFLICT (tenant_id, pubkey) DO NOTHING
                         RETURNING 1
                     ), revoked AS (
                         DELETE FROM og_diviner_grants g
                         WHERE g.tenant_id = $1
                           AND g.pubkey IN (SELECT pubkey FROM deleted)
                         RETURNING 1
                     )
                     SELECT (SELECT count(*) FROM inserted),
                            (SELECT count(*) FROM revoked),
                            (SELECT count(*) FROM deleted)",
                )
                .bind(tenant_id)
                .bind(roster.pubkeys())
                .bind(evidence.as_str())
                .fetch_one(&mut *tx)
                .await?;
            let (newly_granted, revoked_deleted, excluded_deleted) = (
                newly_granted as u64,
                revoked_deleted as u64,
                excluded_deleted as u64,
            );
            // One snapshot means this cannot fail. If it ever does, the report
            // could not account for what was written, so roll back rather than
            // commit a load nobody can describe.
            let Some(already_granted) = unique.checked_sub(newly_granted + excluded_deleted) else {
                return Err(RepositoryError::Integrity(
                    "grant counts do not add up to the roster; nothing loaded".to_string(),
                ));
            };
            tx.commit().await?;
            (
                newly_granted,
                already_granted,
                excluded_deleted,
                revoked_deleted,
            )
        } else {
            // Defines "deleted" the same way the load does. Kept as a join
            // against that one set rather than an EXISTS per count: Postgres
            // inlines a per-row EXISTS into each FILTER and scans the deletion
            // records once per roster row per count, which takes minutes on a
            // full roster.
            let (already, excluded, revoked): (i64, i64, i64) = sqlx::query_as(
                "WITH roster AS (
                     SELECT unnest($2::text[]) AS pubkey
                 ), deleted AS (
                     SELECT r.pubkey FROM roster r
                     WHERE EXISTS (
                         SELECT 1 FROM service_account_deletions d
                         WHERE d.tenant_id = $1 AND d.user_pubkey = r.pubkey
                     )
                 )
                 SELECT
                     count(*) FILTER (WHERE g.pubkey IS NOT NULL AND x.pubkey IS NULL),
                     count(x.pubkey),
                     count(*) FILTER (WHERE g.pubkey IS NOT NULL AND x.pubkey IS NOT NULL)
                 FROM roster r
                 LEFT JOIN og_diviner_grants g ON g.tenant_id = $1 AND g.pubkey = r.pubkey
                 LEFT JOIN deleted x ON x.pubkey = r.pubkey",
            )
            .bind(tenant_id)
            .bind(roster.pubkeys())
            .fetch_one(&self.pool)
            .await?;
            // One statement over the roster with disjoint filters, so these
            // never exceed `unique`.
            let (already, excluded) = (already as u64, excluded as u64);
            (
                unique - already - excluded,
                already,
                excluded,
                revoked as u64,
            )
        };

        Ok(GrantLoadReport {
            tenant_domain,
            tenant_name,
            unique: unique as usize,
            newly_granted,
            already_granted,
            excluded_deleted,
            revoked_deleted,
            applied: apply,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: char) -> String {
        format!("06d3{}", std::iter::repeat_n(seed, 60).collect::<String>())
    }

    #[test]
    fn evidence_labels_round_trip_and_unknown_labels_are_rejected() {
        let evidence: OgDivinerGrantEvidence = "pre_cutoff_app_post".parse().unwrap();
        assert_eq!(evidence, OgDivinerGrantEvidence::PreCutoffAppPost);
        assert_eq!(evidence.as_str(), "pre_cutoff_app_post");
        assert!("PRE_CUTOFF_APP_POST"
            .parse::<OgDivinerGrantEvidence>()
            .is_err());
        assert!("app_post".parse::<OgDivinerGrantEvidence>().is_err());
    }

    #[test]
    fn skips_blank_lines_and_surrounding_whitespace() {
        let input = format!("\n  {}  \r\n\r\n{}\n", key('a'), key('b'));

        let roster = parse_grant_roster(&input).unwrap();

        assert_eq!(roster.entries(), 2);
        assert_eq!(roster.pubkeys(), [key('a'), key('b')]);
        assert_eq!(roster.duplicates(), 0);
    }

    #[test]
    fn collapses_duplicates_and_counts_them() {
        let input = format!("{}\n{}\n{}\n", key('a'), key('b'), key('a'));

        let roster = parse_grant_roster(&input).unwrap();

        assert_eq!(roster.entries(), 3);
        assert_eq!(roster.pubkeys(), [key('a'), key('b')]);
        assert_eq!(roster.duplicates(), 1);
    }

    fn malformed_lines() -> Vec<String> {
        vec![
            format!("\u{feff}{}", key('a')),
            key('b'),
            key('c').to_uppercase(),
            format!("npub1{}", "q".repeat(58)),
            key('d')[..63].to_string(),
            format!("{}0", key('e')),
            key('f').replace('f', "g"),
        ]
    }

    #[test]
    fn rejects_every_malformed_line_by_number() {
        let input = malformed_lines().join("\n");

        let error = parse_grant_roster(&input).unwrap_err();

        assert_eq!(
            error,
            GrantRosterError::InvalidLines {
                count: 6,
                first: vec![1, 3, 4, 5, 6, 7],
            }
        );
    }

    #[test]
    fn error_messages_carry_line_numbers_but_never_line_contents() {
        let lines = malformed_lines();

        let message = parse_grant_roster(&lines.join("\n"))
            .unwrap_err()
            .to_string();

        assert!(message.contains("1, 3, 4, 5, 6, 7"), "got {message}");
        for line in &lines {
            assert!(!message.contains(line.trim()), "message echoed a line");
        }
    }

    #[test]
    fn line_numbers_are_file_lines_counting_blank_ones() {
        let input = format!("\n{}\n\nnot-a-key\n", key('a'));

        let error = parse_grant_roster(&input).unwrap_err();

        assert_eq!(
            error,
            GrantRosterError::InvalidLines {
                count: 1,
                first: vec![4],
            },
            "an operator finds the bad line by its number in the file"
        );
    }

    #[test]
    fn reports_at_most_ten_line_numbers() {
        let input = vec!["not-a-key"; 25].join("\n");

        let GrantRosterError::InvalidLines { count, first } =
            parse_grant_roster(&input).unwrap_err()
        else {
            panic!("expected invalid lines");
        };

        assert_eq!(count, 25);
        assert_eq!(first, (1..=10).collect::<Vec<_>>());
    }

    #[test]
    fn rejects_a_roster_with_no_pubkeys() {
        assert_eq!(parse_grant_roster(""), Err(GrantRosterError::Empty));
        assert_eq!(parse_grant_roster(" \n\r\n"), Err(GrantRosterError::Empty));
    }

    #[test]
    fn debug_output_redacts_the_roster() {
        let roster = parse_grant_roster(&key('a')).unwrap();

        let debug = format!("{roster:?}");

        assert!(!debug.contains(&key('a')), "Debug echoed a pubkey: {debug}");
        assert!(debug.contains("entries: 1"), "got {debug}");
    }
}
