// ABOUTME: Email service abstraction for sending verification and password reset emails
// ABOUTME: Supports SendGrid for production and DevEmailSender for local development/testing

use async_trait::async_trait;
use serde::Serialize;
use std::env;
use std::sync::{Arc, Mutex};

/// Captured email for testing/inspection
#[derive(Debug, Clone)]
pub struct CapturedEmail {
    pub to: String,
    pub subject: String,
    pub verification_url: Option<String>,
    pub reset_url: Option<String>,
}

/// Trait for email sending - allows swapping implementations for testing
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String>;
    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String>;

    /// Send a claim link email for a preloaded Vine account.
    async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String>;

    /// Get captured emails (only available in dev/test mode)
    fn get_captured_emails(&self) -> Vec<CapturedEmail> {
        vec![]
    }

    /// Clear captured emails (only available in dev/test mode)
    fn clear_captured_emails(&self) {
        // No-op by default
    }
}

/// Development email sender - logs URLs to console and captures emails for testing
pub struct DevEmailSender {
    base_url: String,
    captured: Arc<Mutex<Vec<CapturedEmail>>>,
}

impl DevEmailSender {
    pub fn new() -> Self {
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        tracing::info!("===========================================");
        tracing::info!("  EMAIL SERVICE: Development Mode");
        tracing::info!("  Emails will be logged to console");
        tracing::info!("  Base URL: {}", base_url);
        tracing::info!("===========================================");

        Self {
            base_url,
            captured: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get a clone of the captured emails storage for sharing with tests
    pub fn captured_emails(&self) -> Arc<Mutex<Vec<CapturedEmail>>> {
        self.captured.clone()
    }
}

impl Default for DevEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailSender for DevEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  VERIFICATION EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Subject: Verify your Divine email address");
        tracing::info!("");
        tracing::info!("  Click to verify:");
        tracing::info!("  {}", verification_url);
        tracing::info!("==================================================");
        tracing::info!("");

        // Also print to stderr so it's visible even with log filtering
        eprintln!(
            "\n\x1b[32m[DEV EMAIL]\x1b[0m Verification link for {}: \x1b[4m{}\x1b[0m\n",
            to_email, verification_url
        );

        // Capture for testing
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: "Verify your Divine email address".to_string(),
                verification_url: Some(verification_url),
                reset_url: None,
            });
        }

        Ok(())
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.base_url, reset_token);

        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  PASSWORD RESET EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Subject: Reset your Divine password");
        tracing::info!("");
        tracing::info!("  Click to reset password:");
        tracing::info!("  {}", reset_url);
        tracing::info!("==================================================");
        tracing::info!("");

        // Also print to stderr so it's visible even with log filtering
        eprintln!(
            "\n\x1b[33m[DEV EMAIL]\x1b[0m Password reset link for {}: \x1b[4m{}\x1b[0m\n",
            to_email, reset_url
        );

        // Capture for testing
        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: "Reset your Divine password".to_string(),
                verification_url: None,
                reset_url: Some(reset_url),
            });
        }

        Ok(())
    }

    async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String> {
        tracing::info!("");
        tracing::info!("==================================================");
        tracing::info!("  VINE CLAIM EMAIL");
        tracing::info!("==================================================");
        tracing::info!("  To: {}", to_email);
        tracing::info!("  Subject: Your Vine account on Divine is ready to claim");
        tracing::info!("");
        tracing::info!("  Claim link:");
        tracing::info!("  {}", claim_url);
        tracing::info!("==================================================");
        tracing::info!("");

        eprintln!(
            "\n\x1b[36m[DEV EMAIL]\x1b[0m Vine claim link for {}: \x1b[4m{}\x1b[0m\n",
            to_email, claim_url
        );

        if let Ok(mut captured) = self.captured.lock() {
            captured.push(CapturedEmail {
                to: to_email.to_string(),
                subject: "Your Vine account on Divine is ready to claim".to_string(),
                verification_url: Some(claim_url.to_string()),
                reset_url: None,
            });
        }

        Ok(())
    }

    fn get_captured_emails(&self) -> Vec<CapturedEmail> {
        self.captured
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn clear_captured_emails(&self) {
        if let Ok(mut captured) = self.captured.lock() {
            captured.clear();
        }
    }
}

// SendGrid API types
#[derive(Debug, Serialize)]
struct SendGridEmail {
    personalizations: Vec<Personalization>,
    from: EmailAddress,
    subject: String,
    content: Vec<Content>,
    tracking_settings: TrackingSettings,
}

#[derive(Debug, Serialize)]
struct TrackingSettings {
    click_tracking: ClickTracking,
    open_tracking: OpenTracking,
}

#[derive(Debug, Serialize)]
struct ClickTracking {
    enable: bool,
}

#[derive(Debug, Serialize)]
struct OpenTracking {
    enable: bool,
}

#[derive(Debug, Serialize)]
struct Personalization {
    to: Vec<EmailAddress>,
}

#[derive(Debug, Serialize)]
struct EmailAddress {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

/// Production email sender using SendGrid API
pub struct SendGridEmailSender {
    api_key: String,
    from_email: String,
    from_name: String,
    base_url: String,
}

impl SendGridEmailSender {
    pub fn new(api_key: String) -> Self {
        let from_email =
            env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@divine.video".to_string());
        let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Divine".to_string());
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        tracing::info!("Email service initialized with SendGrid");

        Self {
            api_key,
            from_email,
            from_name,
            base_url,
        }
    }

    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_content: &str,
        text_content: &str,
    ) -> Result<(), String> {
        // Check if emails are disabled (useful for load testing)
        if env::var("DISABLE_EMAILS").is_ok() {
            tracing::info!(
                "Emails disabled via DISABLE_EMAILS env var, skipping email to {}",
                to_email
            );
            return Ok(());
        }

        let email = SendGridEmail {
            personalizations: vec![Personalization {
                to: vec![EmailAddress {
                    email: to_email.to_string(),
                    name: None,
                }],
            }],
            from: EmailAddress {
                email: self.from_email.clone(),
                name: Some(self.from_name.clone()),
            },
            subject: subject.to_string(),
            content: vec![
                Content {
                    content_type: "text/plain".to_string(),
                    value: text_content.to_string(),
                },
                Content {
                    content_type: "text/html".to_string(),
                    value: html_content.to_string(),
                },
            ],
            // Disable tracking for security-sensitive emails (verification, password reset)
            // to prevent tokens from passing through SendGrid's redirect servers
            tracking_settings: TrackingSettings {
                click_tracking: ClickTracking { enable: false },
                open_tracking: OpenTracking { enable: false },
            },
        };

        let client = reqwest::Client::new();
        let response = client
            .post("https://api.sendgrid.com/v3/mail/send")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&email)
            .send()
            .await
            .map_err(|e| format!("Failed to send email: {}", e))?;

        if response.status().is_success() {
            tracing::info!("Email sent successfully to {}", to_email);
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Could not read response body".to_string());
            tracing::error!("SendGrid API error: {} - {}", status, body);
            Err(format!("Failed to send email: {} - {}", status, body))
        }
    }
}

#[async_trait]
impl EmailSender for SendGridEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );

        let subject = "Verify your Divine email address".to_string();
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Verify your Divine email</h1>
                <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>
                <div style="margin: 30px 0;">
                    <a href="{}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Verify Email Address
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{}" style="color: #00B488;">{}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    If you didn't sign up for Divine, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            verification_url, verification_url, verification_url
        );

        let text_content = format!(
            "Thanks for signing up! Please verify your email address by clicking this link:\n\n{}\n\nIf you didn't sign up for Divine, you can safely ignore this email.",
            verification_url
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.base_url, reset_token);

        let subject = "Reset your Divine password".to_string();
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Reset your Divine password</h1>
                <p>We received a request to reset your password. Click the button below to set a new password:</p>
                <div style="margin: 30px 0;">
                    <a href="{}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Reset Password
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{}" style="color: #00B488;">{}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    This link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            reset_url, reset_url, reset_url
        );

        let text_content = format!(
            "We received a request to reset your password. Click this link to set a new password:\n\n{}\n\nThis link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.",
            reset_url
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String> {
        let subject = "Your Vine account on Divine is ready to claim".to_string();
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #00B488;">Your Vine account is ready!</h1>
                <p>Your Vine account has been migrated to Divine. Click the button below to claim it and set up your login:</p>
                <div style="margin: 30px 0;">
                    <a href="{}"
                       style="background: #00B488; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Claim Your Account
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{}" style="color: #00B488;">{}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    This link will expire in 14 days. If you didn't request this, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            claim_url, claim_url, claim_url
        );

        let text_content = format!(
            "Your Vine account has been migrated to Divine. Click this link to claim it:\n\n{}\n\nThis link will expire in 14 days. If you didn't request this, you can safely ignore this email.",
            claim_url
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }
}

/// Create the appropriate email sender based on environment
/// - If SENDGRID_API_KEY is set and non-empty: use SendGrid (production)
/// - If running in production without SENDGRID_API_KEY and without DISABLE_EMAILS: fail with error
/// - Otherwise (development): use DevEmailSender as fallback
pub fn create_email_sender() -> Result<Arc<dyn EmailSender>, String> {
    if let Ok(api_key) = env::var("SENDGRID_API_KEY") {
        if !api_key.is_empty() {
            return Ok(Arc::new(SendGridEmailSender::new(api_key)));
        }
    }

    let env_mode = env::var("RUST_ENV")
        .or_else(|_| env::var("NODE_ENV"))
        .unwrap_or_else(|_| "development".to_string());
    if env_mode == "production"
        && env::var("DISABLE_EMAILS")
            .ok()
            .filter(|v| v == "true")
            .is_none()
    {
        return Err(
            "SENDGRID_API_KEY required in production (set DISABLE_EMAILS=true to override)"
                .to_string(),
        );
    }

    tracing::warn!("SENDGRID_API_KEY not set - using development email sender");
    Ok(Arc::new(DevEmailSender::new()))
}

/// Legacy EmailService for backward compatibility during migration
/// TODO: Remove once all usages are migrated to the trait
pub struct EmailService {
    inner: Arc<dyn EmailSender>,
}

impl EmailService {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            inner: create_email_sender()?,
        })
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        self.inner
            .send_verification_email(to_email, verification_token)
            .await
    }

    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String> {
        self.inner
            .send_password_reset_email(to_email, reset_token)
            .await
    }

    pub async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String> {
        self.inner.send_claim_email(to_email, claim_url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serial test lock to prevent env var races between tests
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper to run a closure with specific env vars set, restoring originals afterward
    fn with_env_vars<F, R>(vars: &[(&str, Option<&str>)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut originals = Vec::new();
        for (key, val) in vars {
            originals.push((*key, env::var(key).ok()));
            match val {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }
        let result = f();
        for (key, original) in originals {
            match original {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }
        result
    }

    #[test]
    fn test_production_without_sendgrid_key_fails() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        let err = result.err().expect("expected an error");
        assert!(
            err.contains("SENDGRID_API_KEY required in production"),
            "unexpected error message: {}",
            err
        );
    }

    #[test]
    fn test_production_with_disable_emails_ok() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", Some("true")),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_production_with_sendgrid_key_ok() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", Some("SG.test-key-value")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_development_without_sendgrid_key_ok() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("RUST_ENV", None),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_production_via_node_env_without_sendgrid_key_fails() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("RUST_ENV", None),
                ("NODE_ENV", Some("production")),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_sendgrid_key_treated_as_unset() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", Some("")),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_disable_emails_still_requires_sendgrid_in_production() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", Some("")),
            ],
            create_email_sender,
        );
        assert!(
            result.is_err(),
            "Empty DISABLE_EMAILS should not bypass production check"
        );
    }
}
