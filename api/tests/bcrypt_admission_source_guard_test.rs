use std::{fs, path::Path};

fn rust_files(root: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(root).expect("read source directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn production_source(source: &str) -> &str {
    let mut offset = 0;
    let mut previous_nonempty = None;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == "mod tests {"
            && previous_nonempty.is_some_and(|attribute: &str| {
                attribute.starts_with("#[cfg(") && attribute.contains("test")
            })
        {
            return &source[..offset];
        }
        if !trimmed.is_empty() {
            previous_nonempty = Some(trimmed);
        }
        offset += line.len();
    }

    source
}

fn directly_uses_bcrypt(source: &str) -> bool {
    let compact: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.contains("bcrypt::hash(")
        || compact.contains("bcrypt::verify(")
        || compact.contains("usebcrypt::hash")
        || compact.contains("usebcrypt::verify")
        || compact.contains("bcryptas")
    {
        return true;
    }

    let mut imports = compact.as_str();
    while let Some(start) = imports.find("usebcrypt::{") {
        let items = &imports[start + "usebcrypt::{".len()..];
        let Some(end) = items.find("};") else {
            return true;
        };
        if items[..end]
            .split(',')
            .any(|item| item.starts_with("hash") || item.starts_with("verify"))
        {
            return true;
        }
        imports = &items[end + 2..];
    }

    false
}

#[test]
fn production_bcrypt_calls_stay_inside_the_admission_service() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let allowed = workspace.join("core/src/bcrypt_admission.rs");
    let mut violations = Vec::new();

    for source_root in ["api/src", "core/src", "signer/src", "keycast/src"] {
        let mut files = Vec::new();
        rust_files(&workspace.join(source_root), &mut files);
        for file in files {
            if file == allowed {
                continue;
            }
            let source = fs::read_to_string(&file).expect("read Rust source");
            if directly_uses_bcrypt(production_source(&source)) {
                violations.push(file);
            }
        }
    }

    assert!(
        violations.is_empty(),
        "direct production bcrypt calls bypass admission: {violations:?}"
    );
}

#[test]
fn cfg_test_helpers_do_not_hide_later_production_calls() {
    let source = r#"
#[cfg(test)]
fn helper() {}

fn production() {
    bcrypt::hash("secret", 4);
}

#[cfg(test)]
mod tests {}
"#;

    assert!(directly_uses_bcrypt(production_source(source)));
}

#[test]
fn imported_or_aliased_bcrypt_calls_are_rejected() {
    assert!(directly_uses_bcrypt(
        "use bcrypt::{DEFAULT_COST, hash as password_hash};"
    ));
    assert!(directly_uses_bcrypt("use bcrypt as password_hash;"));
}
