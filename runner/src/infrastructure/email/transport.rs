//! Outbound email transport.
//!
//! Lifted from the `site_conductor` backend so both planes send through the same
//! seam and the same "unconfigured ⇒ silent no-op" contract. The port exists so the
//! provider is a one-file swap: Gmail's SMTP relay is a starting point with a daily
//! ceiling, not a permanent decision, and nothing above this trait knows which
//! provider is behind it.

use async_trait::async_trait;
use domain::error::DomainError;
use lettre::{
	AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
	message::{
		Mailbox, MultiPart,
		header::{Header, HeaderName, HeaderValue},
	},
	transport::smtp::authentication::Credentials,
};

/// `List-Unsubscribe` (RFC 2369) — lettre 0.11 ships no typed header for it, so
/// declare one rather than reach for a raw-header escape hatch.
#[derive(Clone)]
struct ListUnsubscribe(String);

impl Header for ListUnsubscribe {
	fn name() -> HeaderName {
		HeaderName::new_from_ascii_str("List-Unsubscribe")
	}

	fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		Ok(Self(s.to_owned()))
	}

	fn display(&self) -> HeaderValue {
		HeaderValue::new(Self::name(), self.0.clone())
	}
}

/// `List-Unsubscribe-Post` (RFC 8058). Its presence alongside a URL target is what
/// makes the unsubscribe genuinely one-click for Gmail: the provider POSTs for the
/// user instead of making them open and navigate a page.
#[derive(Clone)]
struct ListUnsubscribePost;

impl Header for ListUnsubscribePost {
	fn name() -> HeaderName {
		HeaderName::new_from_ascii_str("List-Unsubscribe-Post")
	}

	fn parse(_s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		Ok(Self)
	}

	fn display(&self) -> HeaderValue {
		HeaderValue::new(Self::name(), "List-Unsubscribe=One-Click".to_owned())
	}
}

#[async_trait]
pub trait EmailTransport: Send + Sync {
	async fn send(&self, from: &str, email: OutgoingEmail) -> Result<(), DomainError>;
}

/// A single rendered message ready to hand to a transport.
#[derive(Clone, Debug)]
pub struct OutgoingEmail {
	pub to: String,
	pub subject: String,
	pub html: String,
	pub text: String,
	/// One-click unsubscribe target. Gmail requires `List-Unsubscribe` (plus the
	/// POST variant) from bulk senders, and without it our mail is far likelier to
	/// be filed as spam — so it is a required field here, not an optional extra.
	pub unsubscribe_url: String,
}

/// Drops mail on the floor (logs it). Used whenever SMTP is unconfigured, so local
/// and CI runs exercise the whole emit → queue → render → "send" path without
/// delivering anything.
pub struct NoopTransport;

#[async_trait]
impl EmailTransport for NoopTransport {
	async fn send(&self, from: &str, email: OutgoingEmail) -> Result<(), DomainError> {
		tracing::info!(%from, to = %email.to, subject = %email.subject, "email suppressed (SMTP unconfigured)");
		Ok(())
	}
}

/// Async SMTP over STARTTLS (587) or implicit TLS (465). Built once and reused;
/// `lettre` keeps an internal connection pool.
pub struct SmtpTransport {
	mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpTransport {
	pub fn try_new(host: &str, port: u16, username: String, password: String) -> Result<Self, DomainError> {
		let builder = if port == 465 {
			AsyncSmtpTransport::<Tokio1Executor>::relay(host)
		} else {
			AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
		}
		.map_err(|e| DomainError::Repository(format!("smtp setup: {e}")))?;
		let mailer = builder.port(port).credentials(Credentials::new(username, password)).build();
		Ok(Self { mailer })
	}
}

fn mailbox(raw: &str) -> Result<Mailbox, DomainError> {
	raw.parse::<Mailbox>().map_err(|e| DomainError::Repository(format!("invalid mailbox {raw}: {e}")))
}

#[async_trait]
impl EmailTransport for SmtpTransport {
	async fn send(&self, from: &str, email: OutgoingEmail) -> Result<(), DomainError> {
		let mut builder = Message::builder().from(mailbox(from)?).to(mailbox(&email.to)?).subject(email.subject.as_str());

		if !email.unsubscribe_url.is_empty() {
			builder = builder.header(ListUnsubscribe(format!("<{}>", email.unsubscribe_url))).header(ListUnsubscribePost);
		}

		let message = builder
			.multipart(MultiPart::alternative_plain_html(email.text, email.html))
			.map_err(|e| DomainError::Repository(format!("build email: {e}")))?;
		self.mailer.send(message).await.map_err(|e| DomainError::Repository(format!("smtp send: {e}")))?;
		Ok(())
	}
}
