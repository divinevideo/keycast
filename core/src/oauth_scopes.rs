// ABOUTME: OAuth 2.0 scope definitions for Nostr event signing permissions
// ABOUTME: Maps OAuth scope strings (e.g., "sign:notes") to Nostr event kinds

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// OAuth scope represents a permission request from a client application
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    pub name: String,
    pub description: String,
    pub event_kinds: Vec<u16>,
    pub category: ScopeCategory,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScopeCategory {
    Social,
    Messaging,
    Financial,
    Data,
    Dangerous,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,      // Read-only or basic social actions
    Moderate,  // Posting, messaging
    Sensitive, // Private messages, personal data
    High,      // Financial operations
    Critical,  // Irreversible actions (deletions, reports)
}

/// Parse a space-separated scope string into individual scopes
/// Example: "sign:notes sign:reactions decrypt:dms" -> [Scope, Scope, Scope]
pub fn parse_scope_string(scope_str: &str) -> Result<Vec<Scope>, String> {
    let scope_names: Vec<&str> = scope_str.split_whitespace().collect();
    let mut scopes = Vec::new();

    for name in scope_names {
        match get_scope_definition(name) {
            Some(scope) => scopes.push(scope),
            None => return Err(format!("Unknown scope: {}", name)),
        }
    }

    Ok(scopes)
}

/// Get all event kinds covered by a list of scopes
pub fn scopes_to_event_kinds(scopes: &[Scope]) -> Vec<u16> {
    let mut kinds: HashSet<u16> = HashSet::new();

    for scope in scopes {
        for kind in &scope.event_kinds {
            kinds.insert(*kind);
        }
    }

    let mut result: Vec<u16> = kinds.into_iter().collect();
    result.sort();
    result
}

/// Get the definition for a specific scope by name
pub fn get_scope_definition(name: &str) -> Option<Scope> {
    ALL_SCOPES.iter().find(|s| s.name == name).cloned()
}

/// Get all available scopes, grouped by category
pub fn get_scopes_by_category() -> Vec<(ScopeCategory, Vec<Scope>)> {
    use ScopeCategory::*;

    vec![
        (
            Social,
            ALL_SCOPES
                .iter()
                .filter(|s| s.category == Social)
                .cloned()
                .collect(),
        ),
        (
            Messaging,
            ALL_SCOPES
                .iter()
                .filter(|s| s.category == Messaging)
                .cloned()
                .collect(),
        ),
        (
            Financial,
            ALL_SCOPES
                .iter()
                .filter(|s| s.category == Financial)
                .cloned()
                .collect(),
        ),
        (
            Data,
            ALL_SCOPES
                .iter()
                .filter(|s| s.category == Data)
                .cloned()
                .collect(),
        ),
        (
            Dangerous,
            ALL_SCOPES
                .iter()
                .filter(|s| s.category == Dangerous)
                .cloned()
                .collect(),
        ),
    ]
}

// ================ SCOPE DEFINITIONS ================

lazy_static::lazy_static! {
    pub static ref ALL_SCOPES: Vec<Scope> = vec![
        // ===== SOCIAL SCOPES =====
        Scope {
            name: "sign:profile".to_string(),
            description: "Update your profile (name, bio, picture)".to_string(),
            event_kinds: vec![0],
            category: ScopeCategory::Social,
            risk_level: RiskLevel::Moderate,
        },

        Scope {
            name: "sign:notes".to_string(),
            description: "Post notes and replies".to_string(),
            event_kinds: vec![1],
            category: ScopeCategory::Social,
            risk_level: RiskLevel::Moderate,
        },

        Scope {
            name: "sign:follows".to_string(),
            description: "Manage your follow list".to_string(),
            event_kinds: vec![3],
            category: ScopeCategory::Social,
            risk_level: RiskLevel::Moderate,
        },

        Scope {
            name: "sign:reactions".to_string(),
            description: "Like and react to posts".to_string(),
            event_kinds: vec![7, 9735],  // Reactions + Zap receipts
            category: ScopeCategory::Social,
            risk_level: RiskLevel::Safe,
        },

        Scope {
            name: "sign:reposts".to_string(),
            description: "Repost and quote notes".to_string(),
            event_kinds: vec![6, 16],
            category: ScopeCategory::Social,
            risk_level: RiskLevel::Moderate,
        },

        Scope {
            name: "sign:all-social".to_string(),
            description: "All basic social actions (post, react, follow)".to_string(),
            event_kinds: vec![0, 1, 3, 6, 7, 16, 9735],
            category: ScopeCategory::Social,
            risk_level: RiskLevel::Moderate,
        },

        // ===== MESSAGING SCOPES =====
        Scope {
            name: "sign:dms".to_string(),
            description: "Send encrypted direct messages".to_string(),
            event_kinds: vec![4, 44],  // NIP-04 and NIP-44
            category: ScopeCategory::Messaging,
            risk_level: RiskLevel::Sensitive,
        },

        Scope {
            name: "decrypt:dms".to_string(),
            description: "Read your encrypted direct messages".to_string(),
            event_kinds: vec![4, 44],  // Permission to decrypt, not sign
            category: ScopeCategory::Messaging,
            risk_level: RiskLevel::Sensitive,
        },

        Scope {
            name: "sign:gift-wraps".to_string(),
            description: "Send gift-wrapped messages (advanced privacy)".to_string(),
            event_kinds: vec![1059],
            category: ScopeCategory::Messaging,
            risk_level: RiskLevel::Sensitive,
        },

        // ===== FINANCIAL SCOPES =====
        Scope {
            name: "sign:zaps".to_string(),
            description: "Send zaps (Lightning payments) ⚠️ Involves money!".to_string(),
            event_kinds: vec![9734],
            category: ScopeCategory::Financial,
            risk_level: RiskLevel::High,
        },

        Scope {
            name: "sign:wallet".to_string(),
            description: "Wallet operations ⚠️ Direct wallet access!".to_string(),
            event_kinds: vec![23194, 23195],
            category: ScopeCategory::Financial,
            risk_level: RiskLevel::Critical,
        },

        // ===== DATA SCOPES =====
        Scope {
            name: "sign:lists".to_string(),
            description: "Manage lists (mutes, pins, bookmarks, etc.)".to_string(),
            event_kinds: vec![10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10015, 10030],
            category: ScopeCategory::Data,
            risk_level: RiskLevel::Moderate,
        },

        Scope {
            name: "sign:long-form".to_string(),
            description: "Create long-form content (articles, blogs)".to_string(),
            event_kinds: vec![30023, 30024, 30030, 30040, 30041, 30078, 30311, 30315, 30402, 30403],
            category: ScopeCategory::Data,
            risk_level: RiskLevel::Moderate,
        },

        // ===== DANGEROUS SCOPES =====
        Scope {
            name: "sign:deletions".to_string(),
            description: "Delete your events ⚠️ Permanent!".to_string(),
            event_kinds: vec![5],
            category: ScopeCategory::Dangerous,
            risk_level: RiskLevel::Critical,
        },

        Scope {
            name: "sign:reports".to_string(),
            description: "File reports and complaints".to_string(),
            event_kinds: vec![1984],
            category: ScopeCategory::Dangerous,
            risk_level: RiskLevel::High,
        },

        // ===== WILDCARD SCOPES =====
        Scope {
            name: "sign:all".to_string(),
            description: "Sign ALL event types ⚠️ Maximum permissions!".to_string(),
            event_kinds: (0..=40000).collect(),  // All event kinds
            category: ScopeCategory::Dangerous,
            risk_level: RiskLevel::Critical,
        },
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scope_string() {
        let result = parse_scope_string("sign:notes sign:reactions").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "sign:notes");
        assert_eq!(result[1].name, "sign:reactions");
    }

    #[test]
    fn test_parse_unknown_scope() {
        let result = parse_scope_string("sign:unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_scopes_to_event_kinds() {
        let scopes = parse_scope_string("sign:notes sign:profile").unwrap();
        let kinds = scopes_to_event_kinds(&scopes);
        assert_eq!(kinds, vec![0, 1]);
    }

    #[test]
    fn test_scope_deduplication() {
        let scopes = parse_scope_string("sign:reactions sign:all-social").unwrap();
        let kinds = scopes_to_event_kinds(&scopes);
        // Should deduplicate kinds 7 and 9735 which appear in both
        assert!(kinds.contains(&7));
        assert!(kinds.contains(&9735));
        assert!(kinds.len() > 2); // all-social includes more kinds
    }

    #[test]
    fn test_get_scopes_by_category() {
        let grouped = get_scopes_by_category();
        assert_eq!(grouped.len(), 5); // 5 categories

        let social_scopes = &grouped[0].1;
        assert!(!social_scopes.is_empty());
    }
}
