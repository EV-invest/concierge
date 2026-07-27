//! Server-rendered transactional emails for the notification plane.
//!
//! Inline hex (not design tokens) is required here: email clients support neither
//! CSS variables nor external stylesheets, so brand colours are inlined per element.
//!
//! The palette below is flattened from `@evinvest/uikit` (`styles/tokens.css`), the
//! same source the Figma `ev/color` variables publish from — keep the two in step
//! when either moves. Kept deliberately identical to the `site_conductor` templates
//! so a person receiving mail from both planes sees one brand.

// Flattened tokens. Mail clients support neither CSS variables nor `color-mix`, so
// the alpha-based semantic tokens are pre-composited against the surface they sit on
// and pasted as opaque hex.
const MIST: &str = "#e6e1d3"; // --color-main-mist
const TEAL: &str = "#2a9d8f"; // --color-main-accent-t1
const HAIR: &str = "#1b2742"; // navy-hairline
const BLACK: &str = "#070d18"; // --color-main-black / --background
const SURFACE: &str = "#081020"; // --color-main-surface
const CARD: &str = "#0c1626"; // --color-main-card / --card
// `--muted-foreground` is mist at 40%, which composites to ~#63676b on the card —
// 3.3:1, under the 4.5:1 that 13px body copy needs. Kept on the same mist ramp but
// at 60% so the label column stays legible in a mail client.
const MUTED: &str = "#8f908e";

const SERIF: &str = "'Playfair Display',Georgia,'Times New Roman',serif";
const SANS: &str = "Inter,-apple-system,'Segoe UI',Arial,Helvetica,sans-serif";

pub struct RenderedEmail {
	pub subject: String,
	pub html: String,
	pub text: String,
}

/// A notification's email copy. `link` is a cabinet-relative path; `cabinet_url` is
/// the origin it hangs off.
pub fn notification(topic_label: &str, title: &str, body: &str, link: &str, occurred_at: i64, cabinet_url: &str, unsubscribe_url: &str) -> RenderedEmail {
	let cabinet = cabinet_url.trim_end_matches('/');
	let target = if link.is_empty() {
		cabinet.to_owned()
	} else {
		format!("{cabinet}/{}", link.trim_start_matches('/'))
	};

	let mut inner = String::new();
	inner.push_str(&eyebrow(topic_label));
	inner.push_str(&heading(title));
	if !body.is_empty() {
		inner.push_str(&paragraph(body));
	}
	inner.push_str(&detail_box(&[("Topic", topic_label.to_owned()), ("As of", fmt_ts(occurred_at))]));
	inner.push_str(&button("Open your cabinet", &target));

	let footer = format!(
		"You are receiving this because you follow {}. This message is a copy — it is already waiting in your cabinet.",
		topic_label
	);
	RenderedEmail {
		subject: format!("{topic_label} — {title}"),
		html: shell(title, &card(&inner), &footer, unsubscribe_url, topic_label),
		text: format!(
			"{topic_label}\n\n{title}\n\n{body}\n\nAs of: {}\n\nOpen your cabinet: {target}\n\n—\n{footer}\nUnsubscribe: {unsubscribe_url}\n",
			fmt_ts(occurred_at)
		),
	}
}

/// The double opt-in mail — the ONLY thing an unconfirmed, account-less subscriber
/// ever receives. Deliberately minimal: no fund content before consent.
pub fn confirm_subscription(topic_label: &str, confirm_url: &str, unsubscribe_url: &str) -> RenderedEmail {
	let mut inner = String::new();
	inner.push_str(&eyebrow("Confirm your subscription"));
	inner.push_str(&heading("One click and you're on the list"));
	inner.push_str(&paragraph(&format!(
		"Someone — we hope you — asked for {topic_label} updates at this address. Confirm below and we'll start sending. If it wasn't you, ignore this message and nothing further will be sent."
	)));
	inner.push_str(&button("Confirm subscription", confirm_url));

	RenderedEmail {
		subject: format!("Confirm your {topic_label} updates"),
		html: shell(
			"Confirm your subscription",
			&card(&inner),
			"You received this once because this address was entered on our site. We send nothing else until you confirm.",
			unsubscribe_url,
			topic_label,
		),
		text: format!(
			"Confirm your subscription\n\nSomeone asked for {topic_label} updates at this address.\n\nConfirm: {confirm_url}\n\nIf it wasn't you, ignore this message — nothing further will be sent.\n"
		),
	}
}

// ── building blocks ────────────────────────────────────────────────────────

fn esc(raw: &str) -> String {
	raw.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn eyebrow(text: &str) -> String {
	format!(
		r#"<p style="margin:0 0 10px;font-family:{SANS};font-size:10px;line-height:14px;font-weight:600;letter-spacing:1.4px;text-transform:uppercase;color:{TEAL};">{}</p>"#,
		esc(text)
	)
}

fn heading(text: &str) -> String {
	format!(
		r#"<h1 style="margin:0 0 14px;font-family:{SERIF};font-size:27px;line-height:36px;font-weight:600;color:{MIST};">{}</h1>"#,
		esc(text)
	)
}

fn paragraph(text: &str) -> String {
	format!(r#"<p style="margin:0 0 14px;font-family:{SANS};font-size:14px;line-height:23px;color:{MIST};">{}</p>"#, esc(text))
}

fn detail_box(rows: &[(&str, String)]) -> String {
	let mut cells = String::new();
	for (i, (label, value)) in rows.iter().enumerate() {
		let border = if i + 1 < rows.len() { format!("border-bottom:1px solid {HAIR};") } else { String::new() };
		cells.push_str(&format!(
			r#"<tr><td style="padding:11px 0;{border}font-family:{SANS};font-size:13px;line-height:17px;color:{MUTED};">{}</td><td align="right" style="padding:11px 0;{border}font-family:{SANS};font-size:13px;line-height:17px;font-weight:600;color:{MIST};">{}</td></tr>"#,
			esc(label),
			esc(value)
		));
	}
	format!(
		r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 14px;background:{BLACK};border:1px solid {HAIR};border-radius:10px;padding:0 18px;">{cells}</table>"#
	)
}

fn button(label: &str, href: &str) -> String {
	format!(
		r#"<table role="presentation" cellpadding="0" cellspacing="0" style="margin:12px 0 0;"><tr><td style="background:{TEAL};border-radius:8px;"><a href="{}" style="display:inline-block;padding:13px 26px;font-family:{SANS};font-size:14px;line-height:18px;font-weight:600;color:{BLACK};text-decoration:none;">{}</a></td></tr></table>"#,
		esc(href),
		esc(label)
	)
}

fn card(inner: &str) -> String {
	format!(
		r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{CARD};border:1px solid {HAIR};border-radius:12px;"><tr><td style="padding:30px;">{inner}</td></tr></table>"#
	)
}

fn shell(preheader: &str, body: &str, footer_context: &str, unsubscribe_url: &str, topic_label: &str) -> String {
	let preheader = esc(preheader);
	let footer_context = esc(footer_context);
	let unsub = esc(unsubscribe_url);
	let topic = esc(topic_label);
	format!(
		r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"></head>
<body style="margin:0;padding:0;background:{BLACK};">
<span style="display:none;max-height:0;overflow:hidden;opacity:0;">{preheader}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{BLACK};padding:32px 12px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;background:{BLACK};border:1px solid {HAIR};border-radius:16px;overflow:hidden;">
<tr><td style="padding:26px 28px;background:{SURFACE};border-bottom:1px solid {HAIR};">
<p style="margin:0 0 3px;font-family:{SANS};font-size:15px;line-height:19px;font-weight:600;letter-spacing:1.2px;color:{MIST};">EV INVESTMENT</p>
<p style="margin:0;font-family:{SANS};font-size:9px;line-height:13px;font-weight:500;letter-spacing:1.26px;text-transform:uppercase;color:{MUTED};">{topic}</p>
</td></tr>
<tr><td style="padding:28px;background:{BLACK};">{body}</td></tr>
<tr><td style="padding:26px 28px 30px;background:{BLACK};border-top:1px solid {HAIR};">
<p style="margin:0 0 8px;font-family:{SANS};font-size:12px;line-height:19px;color:{MUTED};">{footer_context}</p>
<p style="margin:0;font-family:{SANS};font-size:12px;line-height:16px;font-weight:500;color:{TEAL};"><a href="{unsub}" style="color:{TEAL};text-decoration:none;">Unsubscribe from this topic</a></p>
</td></tr>
</table>
</td></tr></table></body></html>"##
	)
}

/// Unix seconds → "27 July 2026". Hand-rolled rather than pulling in `time`'s
/// `formatting` feature for one date shape.
fn fmt_ts(ts: i64) -> String {
	let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(ts) else {
		return "—".to_owned();
	};
	let month = match dt.month() {
		time::Month::January => "January",
		time::Month::February => "February",
		time::Month::March => "March",
		time::Month::April => "April",
		time::Month::May => "May",
		time::Month::June => "June",
		time::Month::July => "July",
		time::Month::August => "August",
		time::Month::September => "September",
		time::Month::October => "October",
		time::Month::November => "November",
		time::Month::December => "December",
	};
	format!("{} {month} {}", dt.day(), dt.year())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn notification_renders_both_parts_and_escapes_user_copy() {
		let mail = notification(
			"Quy Nhon Fund",
			"NAV is now $1.0842 per unit",
			"Net asset value rose 1.4% <this> month.",
			"/funds/quy-nhon",
			1_785_143_640,
			"https://evinvest.ltd/cabinet",
			"https://evinvest.ltd/u/tok",
		);
		assert!(mail.subject.starts_with("Quy Nhon Fund —"), "subject leads with the topic so a threaded inbox groups sensibly");
		assert!(mail.html.contains("&lt;this&gt;"), "body copy is HTML-escaped — emitters pass through arbitrary text");
		assert!(!mail.text.is_empty(), "a text/plain alternative is always present; html-only mail scores as spam");
		assert!(
			mail.html.contains("https://evinvest.ltd/cabinet/funds/quy-nhon"),
			"the relative link is joined onto the cabinet origin exactly once"
		);
		assert!(
			mail.html.contains("https://evinvest.ltd/u/tok"),
			"the unsubscribe target is rendered in the footer, not only in headers"
		);
	}

	#[test]
	fn confirmation_mail_carries_no_fund_content() {
		let mail = confirm_subscription("Quy Nhon Fund", "https://evinvest.ltd/c/tok", "https://evinvest.ltd/u/tok");
		assert!(mail.html.contains("https://evinvest.ltd/c/tok"), "the confirm link must be present or the opt-in cannot complete");
		assert!(
			!mail.html.contains("NAV") && !mail.html.contains("distribution"),
			"nothing substantive may reach an address before it has confirmed"
		);
	}

	#[test]
	fn timestamp_formats_and_survives_garbage() {
		assert_eq!(fmt_ts(1_785_143_640), "27 July 2026");
		assert_eq!(fmt_ts(i64::MAX), "—", "an out-of-range timestamp degrades instead of panicking the dispatcher");
	}
}
