// ABOUTME: "Continue with Apple / Google" on the hosted login page (GET /api/oauth/authorize)
// ABOUTME: Renders the buttons, loads Sign in with Apple JS and Google Identity Services, posts the token

use super::html_safety::js_string_literal;
use super::social_login::LoginPageSocialConfig;

/// Sign in with Apple JS, served by Apple.
pub const APPLE_JS_URL: &str =
    "https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js";
/// Google Identity Services, served by Google.
pub const GOOGLE_IDENTITY_SERVICES_URL: &str = "https://accounts.google.com/gsi/client";

/// Apple's logo glyph, the same one the mobile app shows on its Apple button.
const APPLE_LOGO_PATH: &str = "M12.138 7.321C11.278 7.321 9.946 6.333 8.544 6.369C6.693 6.393 4.996 7.452 4.042 9.131C2.121 12.499 3.547 17.475 5.421 20.213C6.34 21.547 7.424 23.046 8.862 22.999C10.241 22.939 10.759 22.094 12.433 22.094C14.094 22.094 14.566 22.999 16.027 22.963C17.512 22.939 18.455 21.606 19.363 20.261C20.411 18.713 20.847 17.214 20.871 17.13C20.836 17.118 17.984 16.011 17.948 12.678C17.925 9.892 20.199 8.559 20.305 8.5C19.009 6.583 17.017 6.369 16.322 6.321C14.507 6.178 12.987 7.321 12.138 7.321ZM15.202 4.512C15.968 3.583 16.475 2.286 16.334 1.0C15.238 1.048 13.918 1.738 13.128 2.667C12.421 3.488 11.808 4.809 11.973 6.071C13.187 6.166 14.436 5.44 15.202 4.512Z";

/// Styles for the provider buttons. Google Identity Services draws Google's button itself, a pill
/// 40px high. Apple's button takes the same shape, outlined like Google's light button, with a
/// logo and title that are pure black on light and pure white on dark, as Apple's custom-button
/// rules require.
pub const STYLES: &str = r#"
        .social_signin {
            margin-bottom: 1.25rem;
        }
        .social_signin[hidden],
        .btn_social[hidden],
        .google_signin[hidden] {
            display: none;
        }
        .social_buttons {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .btn_social {
            width: 100%;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0 1rem;
            border: 1px solid #747775;
            border-radius: 9999px;
            background: #FFFFFF;
            color: #000000;
            font-family: -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
        }
        .btn_social:disabled {
            cursor: default;
        }
        .btn_social:focus-visible {
            outline: 2px solid var(--divine-green);
            outline-offset: 2px;
        }
        .btn_social svg {
            width: 18px;
            height: 18px;
            flex-shrink: 0;
        }
        .google_signin {
            display: flex;
            justify-content: center;
            min-height: 40px;
        }
        .social_divider {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-top: 1.25rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        .social_divider::before,
        .social_divider::after {
            content: '';
            flex: 1;
            border-top: 1px solid var(--border);
        }
        @media (prefers-color-scheme: dark) {
            .btn_social {
                background: #131314;
                border-color: #8E918F;
                color: #FFFFFF;
            }
        }
"#;

/// The buttons, above the email form: Apple first, then Google.
pub fn section_html(config: &LoginPageSocialConfig) -> String {
    let apple = if config.apple.is_some() {
        // Enabled once Sign in with Apple JS has loaded.
        format!(
            r#"
                    <button type="button" id="apple_signin" class="btn_social" onclick="keycastSignInWithApple()" disabled>
                        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="{APPLE_LOGO_PATH}"/></svg>
                        <span>Continue with Apple</span>
                    </button>"#
        )
    } else {
        String::new()
    };
    let google = if config.google_client_id.is_some() {
        // Google Identity Services renders its own button here.
        r#"
                    <div id="google_signin" class="google_signin"></div>"#
    } else {
        ""
    };
    format!(
        r#"
            <div id="social_signin" class="social_signin">
                <div class="social_buttons">{apple}{google}
                </div>
                <div class="social_divider">or</div>
            </div>
"#
    )
}

/// The page script, then the provider libraries for the configured providers.
pub fn scripts(config: &LoginPageSocialConfig) -> String {
    let page_config = serde_json::json!({
        "nonce": config.nonce_hash,
        "google": config.google_client_id.as_ref().map(|client_id| serde_json::json!({
            "clientId": client_id,
        })),
        "apple": config.apple.as_ref().map(|apple| serde_json::json!({
            "servicesId": apple.services_id,
            "redirectUri": apple.redirect_uri,
        })),
    });
    let mut html = SCRIPT.replace("__SOCIAL_CONFIG__", &js_string_literal(&page_config));
    if config.apple.is_some() {
        html.push_str(&format!(
            r#"
    <script src="{APPLE_JS_URL}" async onload="keycastInitApple()" onerror="keycastProviderFailed('apple')"></script>"#
        ));
    }
    if config.google_client_id.is_some() {
        html.push_str(&format!(
            r#"
    <script src="{GOOGLE_IDENTITY_SERVICES_URL}" async onload="keycastInitGoogle()" onerror="keycastProviderFailed('google')"></script>"#
        ));
    }
    html
}

/// Runs after the page script, whose `clientId`, `redirectUri`, `showForm`, `showError` and
/// `hideError` it uses.
const SCRIPT: &str = r#"
    <script>
        (function () {
            const config = __SOCIAL_CONFIG__;
            const section = document.getElementById('social_signin');
            const appleButton = document.getElementById('apple_signin');
            const googleButton = document.getElementById('google_signin');
            const darkScheme = window.matchMedia('(prefers-color-scheme: dark)');
            const appleState = Array.from(
                window.crypto.getRandomValues(new Uint8Array(16)),
                (byte) => byte.toString(16).padStart(2, '0')
            ).join('');
            let busy = false;

            // The section disappears when no provider can be offered after all.
            function hideProvider(element) {
                if (element) element.hidden = true;
                const anyShown = [appleButton, googleButton].some((el) => el && !el.hidden);
                if (!anyShown) section.hidden = true;
            }

            window.keycastProviderFailed = function (provider) {
                hideProvider(provider === 'apple' ? appleButton : googleButton);
            };

            async function submit(provider, idToken, authorizationCode) {
                if (busy) return;
                busy = true;
                if (appleButton) appleButton.disabled = true;
                hideError();
                try {
                    const response = await fetch('/api/oauth/social-login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({
                            provider,
                            id_token: idToken,
                            authorization_code: authorizationCode || undefined,
                            client_id: clientId,
                            redirect_uri: redirectUri
                        })
                    });
                    if (!response.ok) {
                        const data = await response.json().catch(() => ({}));
                        // The email form is how an existing password account signs in.
                        if (data.code === 'ACCOUNT_LINK_REQUIRED') showForm('login');
                        showError(data.error || 'Sign-in failed. Please try again.');
                        return;
                    }
                    // Session cookie is set: reload the authorize page, exactly as after a
                    // password sign-in.
                    const url = new URL(window.location.href);
                    url.searchParams.delete('prompt');
                    url.searchParams.delete('byok_pubkey');
                    url.searchParams.delete('default_register');
                    window.location.href = url.toString();
                } catch (e) {
                    showError('Request failed: ' + e.message);
                } finally {
                    busy = false;
                    if (appleButton) appleButton.disabled = false;
                }
            }

            // Google Identity Services draws its own button, at most 400px wide, in Google's
            // light (outline) or dark (filled_black) style.
            let googleWidth = 0;
            function renderGoogle(force) {
                const width = Math.max(200, Math.min(400, Math.floor(googleButton.clientWidth)));
                if (!force && width === googleWidth) return;
                googleWidth = width;
                googleButton.replaceChildren();
                google.accounts.id.renderButton(googleButton, {
                    type: 'standard',
                    theme: darkScheme.matches ? 'filled_black' : 'outline',
                    size: 'large',
                    text: 'continue_with',
                    shape: 'pill',
                    logo_alignment: 'left',
                    width: width,
                    // The rest of the page is English.
                    locale: 'en'
                });
            }

            window.keycastInitGoogle = function () {
                if (!config.google || !window.google || !google.accounts || !google.accounts.id) {
                    hideProvider(googleButton);
                    return;
                }
                google.accounts.id.initialize({
                    client_id: config.google.clientId,
                    nonce: config.nonce,
                    callback: (response) => submit('google', response.credential),
                    ux_mode: 'popup',
                    auto_select: false,
                    context: 'signin'
                });
                renderGoogle(true);
                // The first layout can still be settling when the library loads, and the card
                // narrows on small screens: keep the button as wide as the others.
                if (window.ResizeObserver) {
                    new ResizeObserver(() => renderGoogle(false)).observe(googleButton);
                }
                darkScheme.addEventListener('change', () => renderGoogle(true));
            };

            // Sign in with Apple JS
            window.keycastInitApple = function () {
                if (!config.apple || !window.AppleID || !AppleID.auth) {
                    hideProvider(appleButton);
                    return;
                }
                // Apple's popup answers only a page on the return URL's origin.
                let returnOrigin = null;
                try {
                    returnOrigin = new URL(config.apple.redirectUri).origin;
                } catch (e) {}
                if (returnOrigin !== window.location.origin) {
                    hideProvider(appleButton);
                    return;
                }
                AppleID.auth.init({
                    clientId: config.apple.servicesId,
                    scope: 'name email',
                    redirectURI: config.apple.redirectUri,
                    state: appleState,
                    nonce: config.nonce,
                    usePopup: true
                });
                appleButton.disabled = false;
            };

            window.keycastSignInWithApple = async function () {
                if (busy) return;
                hideError();
                let result;
                try {
                    result = await AppleID.auth.signIn();
                } catch (error) {
                    const reason = error && error.error;
                    if (reason === 'popup_closed_by_user' || reason === 'user_cancelled_authorize') return;
                    if (reason === 'popup_blocked_by_browser') {
                        showError('Allow pop-ups for this page, then try Continue with Apple again.');
                        return;
                    }
                    showError('Sign in with Apple did not finish. Please try again.');
                    return;
                }
                const authorization = result && result.authorization;
                if (!authorization || authorization.state !== appleState || !authorization.id_token) {
                    showError('Sign in with Apple did not finish. Please try again.');
                    return;
                }
                await submit('apple', authorization.id_token, authorization.code);
            };
        })();
    </script>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::social_identity::AppleWebSettings;

    fn config(google: bool, apple: bool) -> LoginPageSocialConfig {
        LoginPageSocialConfig {
            google_client_id: google.then(|| "web.apps.googleusercontent.com".to_string()),
            apple: apple.then(|| AppleWebSettings {
                services_id: "co.example.web".to_string(),
                redirect_uri: "https://login.example/api/oauth/authorize".to_string(),
            }),
            nonce_hash: "ab".repeat(32),
            nonce_cookie: String::new(),
        }
    }

    #[test]
    fn apple_comes_before_google() {
        let html = section_html(&config(true, true));
        let apple = html.find("id=\"apple_signin\"").expect("Apple button");
        let google = html.find("id=\"google_signin\"").expect("Google button");
        assert!(apple < google);
    }

    #[test]
    fn only_configured_providers_are_rendered_and_loaded() {
        let google_only = config(true, false);
        assert!(!section_html(&google_only).contains("apple_signin"));
        let scripts_html = scripts(&google_only);
        assert!(scripts_html.contains(GOOGLE_IDENTITY_SERVICES_URL));
        assert!(!scripts_html.contains(APPLE_JS_URL));

        let apple_only = config(false, true);
        assert!(!section_html(&apple_only).contains("google_signin"));
        let scripts_html = scripts(&apple_only);
        assert!(scripts_html.contains(APPLE_JS_URL));
        assert!(!scripts_html.contains(GOOGLE_IDENTITY_SERVICES_URL));
    }

    #[test]
    fn the_page_gets_the_nonce_hash_and_public_client_ids() {
        let html = scripts(&config(true, true));
        assert!(html.contains(&"ab".repeat(32)));
        assert!(html.contains("web.apps.googleusercontent.com"));
        assert!(html.contains("co.example.web"));
        assert!(!html.contains("__SOCIAL_CONFIG__"));
    }

    #[test]
    fn configured_values_cannot_close_the_script() {
        let mut hostile = config(true, false);
        hostile.google_client_id = Some("</script><script>alert(1)</script>".to_string());
        let html = scripts(&hostile);
        assert!(!html.contains("</script><script>alert(1)"));
    }
}
