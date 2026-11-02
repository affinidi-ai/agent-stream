use anyhow::{Context, Result};
use lettre::message::{Mailbox, MultiPart, SinglePart, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message, SmtpTransport, Transport};
use serde_json::Value as JsonValue;
use tracing::{debug, error, info, warn};

use crate::integrations::destinations;

/// Configuration for SMTP email sending
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from: String,
    pub to: Vec<String>,
    pub use_tls: bool,
    pub use_starttls: Option<bool>,
    pub cc: Option<Vec<String>>,
    pub bcc: Option<Vec<String>>,
}

/// How [`send_email`] secures its SMTP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Implicit TLS (SMTPS), always on port 465.
    ImplicitTls,
    /// STARTTLS, always on port 587.
    StartTls,
    /// No TLS: credentials and mail cross the network in the clear.
    Plaintext,
}

impl SmtpSecurity {
    pub fn of(
        port: u16,
        use_tls: bool,
        use_starttls: Option<bool>,
    ) -> Self {
        if port == 465 || (use_tls && port != 587) {
            Self::ImplicitTls
        } else if port == 587 || use_starttls.unwrap_or(true) {
            Self::StartTls
        } else {
            Self::Plaintext
        }
    }

    /// The security a send with this integration configuration would use, with
    /// the defaults of [`SmtpConfig::from_json`]; `None` when the port is unusable.
    pub fn of_configuration(config: &serde_json::Map<String, JsonValue>) -> Option<Self> {
        let port = config
            .get("smtp_port")
            .and_then(JsonValue::as_u64)
            .and_then(|port| u16::try_from(port).ok())?;
        let use_tls = config
            .get("use_tls")
            .and_then(JsonValue::as_bool)
            .unwrap_or(true);
        let use_starttls = config
            .get("use_starttls")
            .and_then(JsonValue::as_bool);
        Some(Self::of(port, use_tls, use_starttls))
    }
}

impl SmtpConfig {
    /// Parse SMTP configuration from JSON
    pub fn from_json(config: &JsonValue) -> Result<Self> {
        debug!("Parsing SMTP configuration from JSON");

        let smtp_host = config["smtp_host"]
            .as_str()
            .context("Missing smtp_host")?
            .to_string();
        debug!("SMTP host: {}", smtp_host);

        let smtp_port = config["smtp_port"]
            .as_u64()
            .context("Missing smtp_port")
            .and_then(|port| u16::try_from(port).context("smtp_port out of range"))?;
        debug!("SMTP port: {}", smtp_port);

        let smtp_username = config["smtp_username"]
            .as_str()
            .context("Missing smtp_username")?
            .to_string();
        debug!("SMTP username configured ({} chars)", smtp_username.len());

        let smtp_password = config["smtp_password"]
            .as_str()
            .context("Missing smtp_password")?
            .to_string();
        debug!("SMTP password provided: {} chars", smtp_password.len());

        let from = config["from"]
            .as_str()
            .context("Missing from address")?
            .to_string();
        debug!("From address: {}", from);

        let to = config["to"]
            .as_array()
            .context("Missing or invalid 'to' array")?
            .iter()
            .filter_map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
            })
            .collect::<Vec<_>>();
        debug!("To addresses: {:?}", to);

        if to.is_empty() {
            anyhow::bail!("At least one recipient email is required");
        }

        let use_tls = config["use_tls"]
            .as_bool()
            .unwrap_or(true);
        let use_starttls = config
            .get("use_starttls")
            .and_then(|v| v.as_bool());
        debug!("TLS settings: use_tls={}, use_starttls={:?}", use_tls, use_starttls);

        let cc = config
            .get("cc")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            });
        if let Some(ref cc_list) = cc {
            debug!("CC addresses: {:?}", cc_list);
        }

        let bcc = config
            .get("bcc")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            });
        if let Some(ref bcc_list) = bcc {
            debug!("BCC addresses: {:?}", bcc_list);
        }

        check_mailbox("from", &from)?;
        for (field, addresses) in [("to", Some(&to)), ("cc", cc.as_ref()), ("bcc", bcc.as_ref())] {
            for address in addresses
                .into_iter()
                .flatten()
            {
                check_mailbox(field, address)?;
            }
        }

        info!("SMTP configuration parsed successfully");

        Ok(Self {
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            from,
            to,
            use_tls,
            use_starttls,
            cc,
            bcc,
        })
    }
}

fn check_mailbox(
    field: &str,
    address: &str,
) -> Result<()> {
    address
        .parse::<Mailbox>()
        .map(|_| ())
        .with_context(|| format!("Invalid {field} address"))
}

/// Send an email through the SMTP server `config` names. `smtp_host` is
/// checked against the strict outbound policy on every send, saved or not, and
/// only the checked address is dialled, so a name that was public when it was
/// saved cannot reach an internal address later.
pub async fn send_email(
    config: &SmtpConfig,
    subject: &str,
    body: &str,
    is_html: bool,
) -> Result<()> {
    let address = destinations::smtp(&config.smtp_host, config.smtp_port).await?;
    deliver(config, &address.ip().to_string(), subject, body, is_html)
}

/// Build the message and send it through `server`, verifying TLS against
/// `smtp_host`.
fn deliver(
    config: &SmtpConfig,
    server: &str,
    subject: &str,
    body: &str,
    is_html: bool,
) -> Result<()> {
    info!("Starting email send to {:?} via SMTP {}:{}", config.to, config.smtp_host, config.smtp_port);

    // Build the email message
    debug!("Building email message with from: {}", config.from);
    let mut email_builder = Message::builder().from(
        config
            .from
            .parse()
            .context("Invalid from address")?,
    );

    // Add primary recipients
    for recipient in &config.to {
        debug!("Adding recipient: {}", recipient);
        email_builder = email_builder.to(recipient
            .parse()
            .context("Invalid to address")?);
    }

    // Add CC recipients
    if let Some(cc_list) = &config.cc {
        for cc_addr in cc_list {
            debug!("Adding CC: {}", cc_addr);
            email_builder = email_builder.cc(cc_addr
                .parse()
                .context("Invalid cc address")?);
        }
    }

    // Add BCC recipients
    if let Some(bcc_list) = &config.bcc {
        for bcc_addr in bcc_list {
            debug!("Adding BCC: {}", bcc_addr);
            email_builder = email_builder.bcc(
                bcc_addr
                    .parse()
                    .context("Invalid bcc address")?,
            );
        }
    }

    email_builder = email_builder.subject(subject);
    debug!(subject_len = subject.len(), "Email subject prepared");

    // Create the email with HTML or plain text body
    debug!("Building email body (is_html: {})", is_html);
    let email = if is_html {
        email_builder
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(strip_html(body)),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(body.to_string()),
                    ),
            )
            .context("Failed to build HTML email")?
    } else {
        email_builder
            .body(body.to_string())
            .context("Failed to build plain text email")?
    };

    info!("Email message built successfully, creating SMTP transport");

    // Create SMTP transport
    let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

    debug!(
        "Creating SMTP transport with TLS settings: use_tls={}, use_starttls={:?}, port={}",
        config.use_tls, config.use_starttls, config.smtp_port
    );

    let builder = SmtpTransport::builder_dangerous(server)
        .credentials(creds)
        .port(config.smtp_port);
    let mailer = match SmtpSecurity::of(config.smtp_port, config.use_tls, config.use_starttls) {
        SmtpSecurity::ImplicitTls => {
            info!("Using implicit TLS/SMTPS (port {})", config.smtp_port);
            builder
                .tls(Tls::Wrapper(TlsParameters::new(config.smtp_host.clone()).context("Failed to create SMTP relay")?))
        }
        SmtpSecurity::StartTls => {
            info!("Using STARTTLS (port {})", config.smtp_port);
            builder.tls(Tls::Required(
                TlsParameters::new(config.smtp_host.clone()).context("Failed to create SMTP STARTTLS relay")?,
            ))
        }
        SmtpSecurity::Plaintext => {
            warn!("Using unencrypted SMTP connection (not recommended for production)");
            builder
        }
    }
    .build();

    info!("SMTP transport created, attempting to send email...");

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            info!(recipient_count = config.to.len(), subject_len = subject.len(), "Email sent successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to send email: {}", e);
            Err(anyhow::anyhow!("SMTP error: {}", e))
        }
    }
}

/// Simple HTML tag stripper for plain text alternative
fn strip_html(html: &str) -> String {
    let mut result = String::new();
    let mut inside_tag = false;

    for ch in html.chars() {
        match ch {
            '<' => {
                if !result.ends_with(' ') {
                    result.push(' ');
                }
                inside_tag = true;
            }
            '>' => {
                inside_tag = false;
                if !result.ends_with(' ') {
                    result.push(' ');
                }
            }
            _ if !inside_tag => result.push(ch),
            _ => {}
        }
    }

    // Clean up excessive whitespace
    result
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_security_follows_port_then_tls_flags() {
        assert_eq!(SmtpSecurity::of(465, false, Some(false)), SmtpSecurity::ImplicitTls);
        assert_eq!(SmtpSecurity::of(587, true, Some(false)), SmtpSecurity::StartTls);
        assert_eq!(SmtpSecurity::of(2525, true, None), SmtpSecurity::ImplicitTls);
        assert_eq!(SmtpSecurity::of(25, false, None), SmtpSecurity::StartTls);
        assert_eq!(SmtpSecurity::of(25, false, Some(false)), SmtpSecurity::Plaintext);
    }

    #[test]
    fn smtp_security_of_configuration_uses_the_parser_defaults() {
        let of = |config: JsonValue| SmtpSecurity::of_configuration(config.as_object().unwrap());

        assert_eq!(of(serde_json::json!({ "smtp_port": 25 })), Some(SmtpSecurity::ImplicitTls));
        assert_eq!(
            of(serde_json::json!({ "smtp_port": 25, "use_tls": false, "use_starttls": false })),
            Some(SmtpSecurity::Plaintext)
        );
        assert_eq!(of(serde_json::json!({ "smtp_port": 70000 })), None);
        assert_eq!(of(serde_json::json!({})), None);
    }

    #[test]
    fn test_strip_html() {
        let html = "<h1>Hello</h1><p>This is a <strong>test</strong> message.</p>";
        let plain = strip_html(html);
        assert_eq!(plain, "Hello This is a test message.");
    }

    #[test]
    fn test_smtp_config_from_json() {
        let config_json = serde_json::json!({
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "user@gmail.com",
            "smtp_password": "app-password",
            "from": "gateway@company.com",
            "to": ["admin@company.com"],
            "use_tls": false,
            "use_starttls": true
        });

        let config = SmtpConfig::from_json(&config_json).unwrap();
        assert_eq!(config.smtp_host, "smtp.gmail.com");
        assert_eq!(config.smtp_port, 587);
        assert_eq!(config.to.len(), 1);
        assert!(!config.use_tls);
        assert_eq!(config.use_starttls, Some(true));
    }

    #[test]
    fn smtp_config_rejects_missing_password() {
        let config_json = serde_json::json!({
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "user@gmail.com",
            "from": "gateway@company.com",
            "to": ["admin@company.com"]
        });

        let err = SmtpConfig::from_json(&config_json).expect_err("missing password must fail");
        assert!(
            err.to_string()
                .contains("Missing smtp_password")
        );
    }

    #[test]
    fn test_smtp_config_rejects_a_malformed_address() {
        for (field, value) in [
            ("from", serde_json::json!("not an address")),
            ("to", serde_json::json!(["ops@example.com", "not an address"])),
            ("cc", serde_json::json!(["not an address"])),
            ("bcc", serde_json::json!(["not an address"])),
        ] {
            let mut config_json = serde_json::json!({
                "smtp_host": "smtp.gmail.com",
                "smtp_port": 587,
                "smtp_username": "user@gmail.com",
                "smtp_password": "app-password",
                "from": "gateway@company.com",
                "to": ["admin@company.com"]
            });
            config_json[field] = value;

            match SmtpConfig::from_json(&config_json) {
                Err(err) => assert_eq!(err.to_string(), format!("Invalid {field} address")),
                Ok(_) => panic!("a malformed {field} address must fail"),
            }
        }
    }

    #[test]
    fn smtp_config_rejects_out_of_range_port() {
        let config_json = serde_json::json!({
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 70000,
            "smtp_username": "user@gmail.com",
            "smtp_password": "app-password",
            "from": "gateway@company.com",
            "to": ["admin@company.com"]
        });

        let err = SmtpConfig::from_json(&config_json).expect_err("invalid port must fail");
        assert!(
            err.to_string()
                .contains("smtp_port out of range")
        );
    }
}
