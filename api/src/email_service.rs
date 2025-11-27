// ABOUTME: SendGrid email service for sending verification and password reset emails
// ABOUTME: Handles all email communications using the SendGrid API

use serde::Serialize;
use std::env;

#[derive(Debug, Serialize)]
struct SendGridEmail {
    personalizations: Vec<Personalization>,
    from: EmailAddress,
    subject: String,
    content: Vec<Content>,
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

pub struct EmailService {
    api_key: String,
    from_email: String,
    from_name: String,
    base_url: String,
}

impl EmailService {
    pub fn new() -> Result<Self, String> {
        let api_key = env::var("SENDGRID_API_KEY")
            .map_err(|_| "SENDGRID_API_KEY environment variable not set".to_string())?;

        let from_email = env::var("FROM_EMAIL")
            .unwrap_or_else(|_| "noreply@keycast.app".to_string());

        let from_name = env::var("FROM_NAME")
            .unwrap_or_else(|_| "diVine".to_string());

        let base_url = env::var("BASE_URL")
            .unwrap_or_else(|_| "https://login.divine.video".to_string());

        Ok(Self {
            api_key,
            from_email,
            from_name,
            base_url,
        })
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), String> {
        let verification_url = format!(
            "{}/verify-email?token={}",
            self.base_url, verification_token
        );

        let subject = "Verify your diVine email address".to_string();
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #bb86fc;">Verify your diVine email</h1>
                <p>Thanks for signing up! Please verify your email address by clicking the button below:</p>
                <div style="margin: 30px 0;">
                    <a href="{}"
                       style="background: #bb86fc; color: #000; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Verify Email Address
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{}" style="color: #bb86fc;">{}</a>
                </p>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    If you didn't sign up for diVine, you can safely ignore this email.
                </p>
            </body>
            </html>
            "#,
            verification_url, verification_url, verification_url
        );

        let text_content = format!(
            "Thanks for signing up! Please verify your email address by clicking this link:\n\n{}\n\nIf you didn't sign up for diVine, you can safely ignore this email.",
            verification_url
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        reset_token: &str,
    ) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.base_url, reset_token);

        let subject = "Reset your diVine password".to_string();
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #bb86fc;">Reset your diVine password</h1>
                <p>We received a request to reset your password. Click the button below to set a new password:</p>
                <div style="margin: 30px 0;">
                    <a href="{}"
                       style="background: #bb86fc; color: #000; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
                        Reset Password
                    </a>
                </div>
                <p style="color: #666; font-size: 14px;">
                    Or copy and paste this link into your browser:<br>
                    <a href="{}" style="color: #bb86fc;">{}</a>
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

    pub async fn send_key_export_code(
        &self,
        to_email: &str,
        code: &str,
    ) -> Result<(), String> {
        let subject = "Your diVine key export verification code".to_string();
        let html_content = format!(
            r#"
            <html>
            <body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #bb86fc;">Key Export Verification Code</h1>
                <p>You requested to export your private key. Use the verification code below to complete the export:</p>
                <div style="margin: 30px 0; padding: 20px; background: #1a1a1a; border-radius: 8px; text-align: center;">
                    <div style="font-size: 32px; font-weight: bold; color: #bb86fc; letter-spacing: 8px; font-family: monospace;">
                        {}
                    </div>
                </div>
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    This code will expire in 10 minutes. If you didn't request a key export, please ignore this email and ensure your account is secure.
                </p>
            </body>
            </html>
            "#,
            code
        );

        let text_content = format!(
            "You requested to export your private key. Use this verification code to complete the export:\n\n{}\n\nThis code will expire in 10 minutes. If you didn't request a key export, please ignore this email and ensure your account is secure.",
            code
        );

        self.send_email(to_email, &subject, &html_content, &text_content)
            .await
    }

    async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        html_content: &str,
        text_content: &str,
    ) -> Result<(), String> {
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
