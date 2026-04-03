// ABOUTME: Shared HTML/attribute/JS escaping helpers to prevent XSS in server-rendered pages
// ABOUTME: All user-controlled values interpolated into HTML must go through these functions

/// Escape a string for safe inclusion in HTML content or attribute contexts.
/// Replaces the five characters that can break out of HTML text or attribute values.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Escape a string for safe inclusion in an HTML attribute value.
/// Currently identical to `escape_html`; kept as a separate function so call sites
/// are self-documenting about context.
pub fn escape_attr(value: &str) -> String {
    escape_html(value)
}

/// Produce a JSON-encoded string literal safe for embedding inside a `<script>` block.
/// The returned value includes the surrounding double quotes, so it can be dropped
/// straight into JS source:  `const x = {js_string_literal(&val)};`
///
/// Because `serde_json::to_string` already JSON-escapes `"`, `\`, and control characters,
/// and the result is always a double-quoted string, it is safe inside `<script>` as long
/// as the surrounding template does not place it inside an HTML attribute.
pub fn js_string_literal<T: serde::Serialize>(value: &T) -> String {
    let s = serde_json::to_string(value).expect("serializable JS literal");
    // Extra defense: replace `</` with `<\/` to prevent closing a <script> tag
    s.replace("</", "<\\/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_escapes_all_special_chars() {
        assert_eq!(
            escape_html(r#"<script>alert("xss")&'</script>"#),
            "&lt;script&gt;alert(&quot;xss&quot;)&amp;&#39;&lt;/script&gt;"
        );
    }

    #[test]
    fn escape_html_empty_string() {
        assert_eq!(escape_html(""), "");
    }

    #[test]
    fn escape_html_no_special_chars() {
        assert_eq!(escape_html("hello world 123"), "hello world 123");
    }

    #[test]
    fn escape_html_all_special_chars_only() {
        assert_eq!(escape_html("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
    }

    #[test]
    fn escape_attr_same_as_escape_html() {
        let input = r#"" onmouseover="alert(1)"#;
        assert_eq!(escape_attr(input), escape_html(input));
    }

    #[test]
    fn js_string_literal_basic() {
        assert_eq!(js_string_literal(&"hello"), r#""hello""#);
    }

    #[test]
    fn js_string_literal_escapes_quotes_and_backslash() {
        assert_eq!(js_string_literal(&r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn js_string_literal_escapes_script_close_tag() {
        let result = js_string_literal(&"</script><img src=x onerror=alert(1)>");
        assert!(
            !result.contains("</script>"),
            "must not contain literal </script>"
        );
        assert!(result.contains("<\\/script>"));
    }

    #[test]
    fn js_string_literal_empty() {
        assert_eq!(js_string_literal(&""), r#""""#);
    }

    #[test]
    fn js_string_literal_with_newlines_and_control_chars() {
        let result = js_string_literal(&"line1\nline2\ttab");
        assert_eq!(result, r#""line1\nline2\ttab""#);
    }

    #[test]
    fn js_string_literal_non_string_serializable() {
        // Verify it works with non-string types too
        assert_eq!(js_string_literal(&42), "42");
        assert_eq!(js_string_literal(&true), "true");
    }
}
