use std::{fs, path::Path};
use syn::{
    punctuated::Punctuated,
    visit::{self, Visit},
    Attribute, Expr, ExprCall, Item, ItemExternCrate, ItemUse, Meta, Token, UseTree,
};

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

fn parse_nested_meta(list: &syn::MetaList) -> Option<Punctuated<Meta, Token![,]>> {
    list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        .ok()
}

fn meta_requires_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("cfg") => parse_nested_meta(list)
            .is_some_and(|nested| nested.len() == 1 && nested.iter().all(meta_requires_test)),
        // `all(test, ...)` requires tests, while `any(test, ...)` and `not(test)` can compile
        // outside tests and must remain visible to the guard.
        Meta::List(list) if list.path.is_ident("all") => {
            parse_nested_meta(list).is_some_and(|nested| nested.iter().any(meta_requires_test))
        }
        Meta::List(_) => false,
        Meta::NameValue(_) => false,
    }
}

fn is_test_only(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") && meta_requires_test(&attribute.meta))
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn imports_bcrypt_work(tree: &UseTree) -> bool {
    match tree {
        UseTree::Name(name) => name.ident == "hash" || name.ident == "verify",
        UseTree::Rename(rename) => {
            rename.ident == "hash" || rename.ident == "verify" || rename.ident == "self"
        }
        UseTree::Path(path) => imports_bcrypt_work(&path.tree),
        UseTree::Group(group) => group.items.iter().any(imports_bcrypt_work),
        UseTree::Glob(_) => true,
    }
}

#[derive(Default)]
struct DirectBcryptVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for DirectBcryptVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if !is_test_only(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(function) = call.func.as_ref() {
            let mut segments = function.path.segments.iter();
            if segments
                .next()
                .is_some_and(|segment| segment.ident == "bcrypt")
                && segments
                    .last()
                    .is_some_and(|segment| segment.ident == "hash" || segment.ident == "verify")
            {
                self.found = true;
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        match &item.tree {
            UseTree::Path(path) if path.ident == "bcrypt" && imports_bcrypt_work(&path.tree) => {
                self.found = true;
            }
            UseTree::Rename(rename) if rename.ident == "bcrypt" => self.found = true,
            _ => {}
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        if item.ident == "bcrypt" && item.rename.is_some() {
            self.found = true;
        }
        visit::visit_item_extern_crate(self, item);
    }
}

fn directly_uses_bcrypt(source: &str) -> bool {
    let syntax = syn::parse_file(source).expect("parse Rust source");
    let mut visitor = DirectBcryptVisitor::default();
    visitor.visit_file(&syntax);
    visitor.found
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
            if directly_uses_bcrypt(&source) {
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

    assert!(directly_uses_bcrypt(source));
}

#[test]
fn early_test_modules_do_not_hide_later_production_calls() {
    let source = r#"
#[cfg(test)]
mod tests {
    fn test_helper() {
        bcrypt::hash("test", 4);
    }
}

fn production() {
    bcrypt::hash("secret", 4);
}
"#;

    assert!(directly_uses_bcrypt(source));
}

#[test]
fn imported_or_aliased_bcrypt_calls_are_rejected() {
    assert!(directly_uses_bcrypt(
        "use bcrypt::{DEFAULT_COST, hash as password_hash};"
    ));
    assert!(directly_uses_bcrypt("use bcrypt as password_hash;"));
    assert!(directly_uses_bcrypt(
        "extern crate bcrypt as password_hash;"
    ));
}

#[test]
fn comments_about_bcrypt_are_not_calls() {
    assert!(!directly_uses_bcrypt(
        "fn work() { /* bcrypt assumes expensive work */ }"
    ));
}

#[test]
fn production_cfg_expressions_are_not_mistaken_for_test_only_code() {
    assert!(directly_uses_bcrypt(
        "#[cfg(not(test))] fn production() { bcrypt::hash(\"secret\", 4); }"
    ));
    assert!(directly_uses_bcrypt(
        "#[cfg(any(test, feature = \"integration-tests\"))] fn production() { bcrypt::hash(\"secret\", 4); }"
    ));
    assert!(!directly_uses_bcrypt(
        "#[cfg(all(test, feature = \"integration-tests\"))] fn helper() { bcrypt::hash(\"test\", 4); }"
    ));
}
