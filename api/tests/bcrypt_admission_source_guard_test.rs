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
            let source = source.split("\n#[cfg(test)]").next().unwrap_or(&source);
            if source.contains("bcrypt::hash(") || source.contains("bcrypt::verify(") {
                violations.push(file);
            }
        }
    }

    assert!(
        violations.is_empty(),
        "direct production bcrypt calls bypass admission: {violations:?}"
    );
}
