// ABOUTME: Email service abstraction for sending verification and password reset emails
// ABOUTME: Supports SendGrid for production and DevEmailSender for local development/testing

use async_trait::async_trait;
#[cfg(feature = "aws")]
use aws_sdk_sesv2::types::{
    Body as SesBody, Content as SesContent, Destination as SesDestination,
    EmailContent as SesEmailContent, Message as SesMessage,
};
#[cfg(feature = "aws")]
use aws_sdk_sesv2::Client as SesClient;
use serde::Serialize;
use std::env;
use std::sync::{Arc, Mutex};
#[cfg(feature = "aws")]
use tokio::sync::OnceCell;

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmailTemplate {
    subject: String,
    html_content: String,
    text_content: String,
}

fn build_verification_email_template(verification_url: &str) -> EmailTemplate {
    EmailTemplate {
        subject: "Verify your Divine email address".to_string(),
        html_content: format!(
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
        ),
        text_content: format!(
            "Thanks for signing up! Please verify your email address by clicking this link:\n\n{}\n\nIf you didn't sign up for Divine, you can safely ignore this email.",
            verification_url
        ),
    }
}

fn build_password_reset_email_template(reset_url: &str) -> EmailTemplate {
    EmailTemplate {
        subject: "Reset your Divine password".to_string(),
        html_content: format!(
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
        ),
        text_content: format!(
            "We received a request to reset your password. Click this link to set a new password:\n\n{}\n\nThis link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email.",
            reset_url
        ),
    }
}

fn build_claim_email_template(claim_url: &str) -> EmailTemplate {
    EmailTemplate {
        subject: "Your Vine account on Divine is ready to claim".to_string(),
        html_content: format!(
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
                    This link will expire in 7 days. If you didn't request this, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            claim_url, claim_url, claim_url
        ),
        text_content: format!(
            "Your Vine account has been migrated to Divine. Click this link to claim it:\n\n{}\n\nThis link will expire in 7 days. If you didn't request this, you can safely ignore this email.",
            claim_url
        ),
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
        let template = build_verification_email_template(&verification_url);

        self.send_email(
            to_email,
            &template.subject,
            &template.html_content,
            &template.text_content,
        )
        .await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.base_url, reset_token);
        let template = build_password_reset_email_template(&reset_url);

        self.send_email(
            to_email,
            &template.subject,
            &template.html_content,
            &template.text_content,
        )
        .await
    }

    async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String> {
        let template = build_claim_email_template(claim_url);

        self.send_email(
            to_email,
            &template.subject,
            &template.html_content,
            &template.text_content,
        )
        .await
    }
}

#[cfg(feature = "aws")]
pub struct SesEmailSender {
    client: OnceCell<SesClient>,
    from_email: String,
    from_name: String,
    base_url: String,
}

#[cfg(feature = "aws")]
impl SesEmailSender {
    pub fn new() -> Self {
        let from_email =
            env::var("FROM_EMAIL").unwrap_or_else(|_| "noreply@divine.video".to_string());
        let from_name = env::var("FROM_NAME").unwrap_or_else(|_| "Divine".to_string());
        let base_url = env::var("BASE_URL")
            .or_else(|_| env::var("APP_URL"))
            .unwrap_or_else(|_| "http://localhost:5173".to_string());

        tracing::info!("Email service initialized with AWS SES");

        Self {
            client: OnceCell::const_new(),
            from_email,
            from_name,
            base_url,
        }
    }

    async fn get_client(&self) -> Result<&SesClient, String> {
        self.client
            .get_or_try_init(|| async {
                let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .load()
                    .await;
                tracing::info!("AWS SES client initialized");
                Ok::<SesClient, String>(SesClient::new(&config))
            })
            .await
    }

    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_content: &str,
        text_content: &str,
    ) -> Result<(), String> {
        if env::var("DISABLE_EMAILS").is_ok() {
            tracing::info!(
                "Emails disabled via DISABLE_EMAILS env var, skipping email to {}",
                to_email
            );
            return Ok(());
        }

        let client = self.get_client().await?;
        let from = format!("{} <{}>", self.from_name, self.from_email);
        let destination = SesDestination::builder().to_addresses(to_email).build();
        let subject_content = SesContent::builder()
            .data(subject)
            .charset("UTF-8")
            .build()
            .map_err(|e| format!("Failed to build SES subject content: {}", e))?;
        let text_part = SesContent::builder()
            .data(text_content)
            .charset("UTF-8")
            .build()
            .map_err(|e| format!("Failed to build SES text content: {}", e))?;
        let html_part = SesContent::builder()
            .data(html_content)
            .charset("UTF-8")
            .build()
            .map_err(|e| format!("Failed to build SES html content: {}", e))?;
        let message = SesMessage::builder()
            .subject(subject_content)
            .body(SesBody::builder().text(text_part).html(html_part).build())
            .build();

        client
            .send_email()
            .from_email_address(from)
            .destination(destination)
            .content(SesEmailContent::builder().simple(message).build())
            .send()
            .await
            .map_err(|e| format!("Failed to send SES email: {}", e))?;

        tracing::info!("Email sent successfully via SES to {}", to_email);
        Ok(())
    }
}

#[cfg(feature = "aws")]
impl Default for SesEmailSender {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "aws")]
#[async_trait]
impl EmailSender for SesEmailSender {
    async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );
        let template = build_verification_email_template(&verification_url);

        self.send_email(
            to_email,
            &template.subject,
            &template.html_content,
            &template.text_content,
        )
        .await
    }

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.base_url, reset_token);
        let template = build_password_reset_email_template(&reset_url);

        self.send_email(
            to_email,
            &template.subject,
            &template.html_content,
            &template.text_content,
        )
        .await
    }

    async fn send_claim_email(&self, to_email: &str, claim_url: &str) -> Result<(), String> {
        let template = build_claim_email_template(claim_url);

        self.send_email(
            to_email,
            &template.subject,
            &template.html_content,
            &template.text_content,
        )
        .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderDecision {
    SendGrid,
    #[cfg(feature = "aws")]
    Ses,
    Dev,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderConfigError {
    MissingSendGridApiKey,
    UnknownProvider(String),
    #[cfg(not(feature = "aws"))]
    SesFeatureDisabled,
}

impl ProviderConfigError {
    fn to_message(&self) -> String {
        match self {
            Self::MissingSendGridApiKey => {
                "EMAIL_PROVIDER=sendgrid requires SENDGRID_API_KEY to be set".to_string()
            }
            Self::UnknownProvider(provider) => format!(
                "Unknown EMAIL_PROVIDER value '{}'; expected one of: sendgrid, ses, dev",
                provider
            ),
            #[cfg(not(feature = "aws"))]
            Self::SesFeatureDisabled => {
                "EMAIL_PROVIDER=ses requires AWS support, but this build was compiled without the aws feature".to_string()
            }
        }
    }
}

fn normalize_email_provider(email_provider_env: Option<&str>) -> Option<String> {
    email_provider_env
        .map(|provider| provider.trim().to_ascii_lowercase())
        .filter(|provider| !provider.is_empty())
}

fn has_sendgrid_key(sendgrid_api_key_env: Option<&str>) -> bool {
    sendgrid_api_key_env
        .map(|key| !key.trim().is_empty())
        .unwrap_or(false)
}

fn decide_provider(
    email_provider_env: Option<&str>,
    sendgrid_api_key_env: Option<&str>,
) -> Result<ProviderDecision, ProviderConfigError> {
    let has_sendgrid_key = has_sendgrid_key(sendgrid_api_key_env);
    let email_provider = normalize_email_provider(email_provider_env);

    match email_provider.as_deref() {
        Some("sendgrid") => {
            if has_sendgrid_key {
                Ok(ProviderDecision::SendGrid)
            } else {
                Err(ProviderConfigError::MissingSendGridApiKey)
            }
        }
        Some("ses") => {
            #[cfg(feature = "aws")]
            {
                Ok(ProviderDecision::Ses)
            }
            #[cfg(not(feature = "aws"))]
            {
                Err(ProviderConfigError::SesFeatureDisabled)
            }
        }
        Some("dev") => Ok(ProviderDecision::Dev),
        Some(other) => Err(ProviderConfigError::UnknownProvider(other.to_string())),
        None => {
            if has_sendgrid_key {
                Ok(ProviderDecision::SendGrid)
            } else {
                Ok(ProviderDecision::Dev)
            }
        }
    }
}

pub fn validate_email_sender_config() -> Result<(), String> {
    let email_provider_env = env::var("EMAIL_PROVIDER").ok();
    let sendgrid_api_key_env = env::var("SENDGRID_API_KEY").ok();

    decide_provider(
        email_provider_env.as_deref(),
        sendgrid_api_key_env.as_deref(),
    )
    .map(|_| ())
    .map_err(|err| err.to_message())
}

/// Create the appropriate email sender based on environment
/// - If EMAIL_PROVIDER is set: use explicit provider (sendgrid/ses/dev)
/// - If EMAIL_PROVIDER is not set: auto-detect (SENDGRID_API_KEY => SendGrid, else Dev)
pub fn create_email_sender() -> Result<Arc<dyn EmailSender>, String> {
    let email_provider_env = env::var("EMAIL_PROVIDER").ok();
    let sendgrid_api_key_env = env::var("SENDGRID_API_KEY").ok();
    let provider_is_explicit = normalize_email_provider(email_provider_env.as_deref()).is_some();

    match decide_provider(
        email_provider_env.as_deref(),
        sendgrid_api_key_env.as_deref(),
    )
    .map_err(|err| err.to_message())?
    {
        ProviderDecision::SendGrid => {
            let api_key = sendgrid_api_key_env
                .filter(|key| !key.trim().is_empty())
                .ok_or_else(|| {
                    "SENDGRID_API_KEY must be set when using SendGrid email sender".to_string()
                })?;

            Ok(Arc::new(SendGridEmailSender::new(api_key)))
        }
        #[cfg(feature = "aws")]
        ProviderDecision::Ses => Ok(Arc::new(SesEmailSender::new())),
        ProviderDecision::Dev => {
            let env_mode = env::var("RUST_ENV")
                .or_else(|_| env::var("NODE_ENV"))
                .unwrap_or_else(|_| "development".to_string());
            let emails_disabled = env::var("DISABLE_EMAILS")
                .ok()
                .is_some_and(|value| value == "true");
            if env_mode == "production" && !emails_disabled {
                return Err("No email provider configured for production (set SENDGRID_API_KEY, EMAIL_PROVIDER=ses with aws build support, or DISABLE_EMAILS=true)".to_string());
            }

            if !provider_is_explicit {
                tracing::warn!("SENDGRID_API_KEY not set - using development email sender");
            }
            Ok(Arc::new(DevEmailSender::new()))
        }
    }
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
    fn verification_template_includes_url_and_subject() {
        let url = "https://example.com/verify-email?token=abc";
        let template = build_verification_email_template(url);

        assert_eq!(template.subject, "Verify your Divine email address");
        assert!(template.html_content.contains(url));
        assert!(template.text_content.contains(url));
        assert!(template.html_content.contains("Verify your Divine email"));
        assert!(template
            .text_content
            .contains("If you didn't sign up for Divine, you can safely ignore this email."));
    }

    #[test]
    fn reset_template_includes_url_and_subject() {
        let url = "https://example.com/reset-password?token=abc";
        let template = build_password_reset_email_template(url);

        assert_eq!(template.subject, "Reset your Divine password");
        assert!(template.html_content.contains(url));
        assert!(template.text_content.contains(url));
        assert!(template.html_content.contains("Reset your Divine password"));
        assert!(template
            .text_content
            .contains("This link will expire in 1 hour."));
    }

    #[test]
    fn claim_template_includes_url_and_subject() {
        let url = "https://example.com/claim?token=abc";
        let template = build_claim_email_template(url);

        assert_eq!(
            template.subject,
            "Your Vine account on Divine is ready to claim"
        );
        assert!(template.html_content.contains(url));
        assert!(template.text_content.contains(url));
        assert!(template
            .html_content
            .contains("Your Vine account has been migrated to Divine."));
        assert!(template
            .text_content
            .contains("This link will expire in 7 days."));
    }

    #[test]
    fn provider_decision_uses_auto_detection_when_unset() {
        assert_eq!(
            decide_provider(None, Some("abc")),
            Ok(ProviderDecision::SendGrid)
        );
        assert_eq!(decide_provider(None, None), Ok(ProviderDecision::Dev));
        assert_eq!(decide_provider(Some(""), None), Ok(ProviderDecision::Dev));
        assert_eq!(
            decide_provider(Some("   "), Some("abc")),
            Ok(ProviderDecision::SendGrid)
        );
    }

    #[test]
    fn provider_decision_honors_sendgrid_and_dev() {
        assert_eq!(
            decide_provider(Some("sendgrid"), Some("abc")),
            Ok(ProviderDecision::SendGrid)
        );
        assert_eq!(
            decide_provider(Some("sendgrid"), None),
            Err(ProviderConfigError::MissingSendGridApiKey)
        );
        assert_eq!(
            decide_provider(Some("dev"), Some("abc")),
            Ok(ProviderDecision::Dev)
        );
    }

    #[test]
    fn provider_decision_rejects_unknown_values() {
        assert_eq!(
            decide_provider(Some("unknown"), Some("abc")),
            Err(ProviderConfigError::UnknownProvider("unknown".to_string()))
        );
        assert_eq!(
            decide_provider(Some("  invalid  "), None),
            Err(ProviderConfigError::UnknownProvider("invalid".to_string()))
        );
    }

    #[cfg(feature = "aws")]
    #[test]
    fn provider_decision_allows_ses_with_aws_feature() {
        assert_eq!(
            decide_provider(Some("ses"), Some("abc")),
            Ok(ProviderDecision::Ses)
        );
    }

    #[cfg(not(feature = "aws"))]
    #[test]
    fn provider_decision_rejects_ses_without_aws_feature() {
        assert_eq!(
            decide_provider(Some("ses"), Some("abc")),
            Err(ProviderConfigError::SesFeatureDisabled)
        );
    }

    #[test]
    fn production_without_provider_fails() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("EMAIL_PROVIDER", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        let err = result.err().expect("expected an error");
        assert!(
            err.contains("No email provider configured for production"),
            "unexpected error message: {}",
            err
        );
    }

    #[test]
    fn production_with_disable_emails_ok() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("EMAIL_PROVIDER", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", Some("true")),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn production_with_sendgrid_key_ok() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", Some("SG.test-key-value")),
                ("EMAIL_PROVIDER", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn development_without_sendgrid_key_ok() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("EMAIL_PROVIDER", None),
                ("RUST_ENV", None),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn production_via_node_env_without_sendgrid_key_fails() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("EMAIL_PROVIDER", None),
                ("RUST_ENV", None),
                ("NODE_ENV", Some("production")),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_sendgrid_key_treated_as_unset() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", Some("")),
                ("EMAIL_PROVIDER", None),
                ("RUST_ENV", Some("production")),
                ("NODE_ENV", None),
                ("DISABLE_EMAILS", None),
            ],
            create_email_sender,
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_disable_emails_still_requires_provider_in_production() {
        let result = with_env_vars(
            &[
                ("SENDGRID_API_KEY", None),
                ("EMAIL_PROVIDER", None),
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
