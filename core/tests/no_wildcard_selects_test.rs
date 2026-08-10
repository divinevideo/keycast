// ABOUTME: Prevents table-wide SELECT projections from entering pooled production query paths.
// ABOUTME: Additive migrations can invalidate cached prepared plans when SELECT * changes shape.

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn production_rust_queries_do_not_select_all_table_columns() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core crate must have a workspace parent");
    let mut violations = Vec::new();

    for source_root in [
        "api/src",
        "core/src",
        "keycast/src",
        "signer/src",
        "tools/loadtest/src",
    ] {
        collect_rust_files(&workspace.join(source_root), &mut violations);
    }

    assert!(
        violations.is_empty(),
        "table-wide SELECT projections are unsafe with cached prepared statements across \
         additive migrations; name the decoded columns explicitly:\n{}",
        violations.join("\n")
    );
}

fn collect_rust_files(directory: &Path, violations: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("read production source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect_rust_files(&path, violations);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            check_file(&path, violations);
        }
    }
}

fn check_file(path: &PathBuf, violations: &mut Vec<String>) {
    // This intentionally scans all source text, including comments. A prose
    // example that contains a wildcard query should teach the safe pattern too.
    let source = fs::read_to_string(path).expect("read Rust source");
    let normalized = source
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
        .replace("select * from unnest", "select columns from unnest");

    if contains_table_wildcard_select(&normalized) {
        violations.push(path.display().to_string());
    }
}

fn contains_table_wildcard_select(source: &str) -> bool {
    let mut remainder = source;

    while let Some(select_offset) = remainder.find("select ") {
        let after_select = &remainder[select_offset + "select ".len()..];
        let Some(from_offset) = after_select.find(" from") else {
            return false;
        };
        let projection = &after_select[..from_offset];
        let has_wildcard = projection
            .split(|character: char| character.is_whitespace() || character == ',')
            .map(|token| token.trim_matches(['"', '#', '\\']))
            .any(|token| token == "*" || token.ends_with(".*"));

        if has_wildcard && !after_select[from_offset..].starts_with(" from unnest") {
            return true;
        }

        remainder = &after_select[from_offset + " from".len()..];
    }

    false
}

#[test]
fn wildcard_detector_covers_bare_and_qualified_table_projections() {
    assert!(contains_table_wildcard_select("select * from users"));
    assert!(contains_table_wildcard_select(
        "select user.* from users user"
    ));
    assert!(contains_table_wildcard_select(
        "select user.*, tenant.id from users user join tenants tenant on true"
    ));
    assert!(!contains_table_wildcard_select(
        "select count(*) from users"
    ));
    assert!(!contains_table_wildcard_select(
        "select * from unnest($1::bigint[])"
    ));
}
