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

/// The target of an owner removal, told their seat is being voted on.
///
/// The link and the code are deliberately separate. A mail gateway will follow the
/// link on its own; only a person who opened this message can type the code, which is
/// what turns a scanned URL into a deliberate act — and the copy says so plainly,
/// because someone who believes a click has already decided is someone who will not
/// come back to finish.
pub fn owner_removal_self_accept(initiator_email: &str, reason: &str, approval_url: &str, code: &str, expires_at: i64) -> RenderedEmail {
	let mut inner = String::new();
	inner.push_str(&eyebrow("Ownership"));
	inner.push_str(&heading("Your owner seat is being voted on"));
	inner.push_str(&paragraph(&format!(
		"{initiator_email} has proposed removing your owner seat. You may accept it, or refuse it — and refusing does not settle it on its own: the other owners can still carry the proposal unanimously."
	)));
	inner.push_str(&paragraph(&format!("Their stated reason: {reason}")));
	inner.push_str(&detail_box(&[("Proposed by", initiator_email.to_owned()), ("Answer by", fmt_ts(expires_at))]));
	inner.push_str(&button("Open the approval page", approval_url));
	inner.push_str(&code_panel(code));
	inner.push_str(&paragraph(
		"Opening the link alone does nothing. Nothing is decided until you enter the code above on that page and choose an answer.",
	));

	RenderedEmail {
		subject: "Your EV Investment owner seat is being voted on".to_owned(),
		html: shell("Your owner seat is being voted on", &card(&inner), FOOTER_SECURITY, "", "Ownership"),
		text: format!(
			"Your owner seat is being voted on\n\n{initiator_email} has proposed removing your owner seat.\n\nReason: {reason}\n\nAnswer by: {}\n\nApproval page: {approval_url}\n\nYour code: {code}\n\nOpening the link alone does nothing — nothing is decided until you enter the code on that page and choose an answer.\n\n—\n{FOOTER_SECURITY}\n",
			fmt_ts(expires_at)
		),
	}
}

/// The money plane asking an owner to approve a revenue payout.
///
/// Everything an approver is agreeing TO is on the page: the full amount, the network,
/// the destination in full, the memo and the payload hash the money plane will
/// re-verify at execution. An owner must be able to approve a thing they can see.
#[allow(clippy::too_many_arguments)]
pub fn payout_approval(
	consilium_id: &str,
	initiator_email: &str,
	network: &str,
	address: &str,
	amount: &str,
	memo: &str,
	payload_hash: &str,
	threshold: u32,
	owner_count: u32,
	expires_at: i64,
	approval_url: &str,
	code: &str,
) -> RenderedEmail {
	let mut inner = String::new();
	inner.push_str(&eyebrow("Treasury"));
	inner.push_str(&heading("A payout needs your approval"));
	inner.push_str(&paragraph(&format!(
		"{initiator_email} has opened a request to pay fund revenue out on-chain. It executes only once {threshold} of {owner_count} owners have approved it."
	)));
	inner.push_str(&detail_box(&[
		("Amount", amount.to_owned()),
		("Network", network.to_owned()),
		("Requested by", initiator_email.to_owned()),
		("Approvals needed", format!("{threshold} of {owner_count}")),
		("Expires", fmt_ts(expires_at)),
		("Request", consilium_id.to_owned()),
	]));
	inner.push_str(&exact_value("Destination address", address));
	inner.push_str(&exact_value("Payload hash", &hash_prefix(payload_hash)));
	if !memo.is_empty() {
		inner.push_str(&paragraph(&format!("Memo: {memo}")));
	}
	inner.push_str(&button("Review and approve", approval_url));
	inner.push_str(&code_panel(code));
	inner.push_str(&paragraph(
		"Opening the link alone approves nothing. Check the destination address above against the one you expect before you enter the code — an approved payout cannot be recalled.",
	));

	RenderedEmail {
		subject: format!("Approve a payout of {amount} on {network}"),
		html: shell("A payout needs your approval", &card(&inner), FOOTER_SECURITY, "", "Treasury"),
		text: format!(
			"A payout needs your approval\n\n{initiator_email} has opened a request to pay fund revenue out on-chain.\n\nAmount: {amount}\nNetwork: {network}\nDestination address: {address}\nPayload hash: {}\nMemo: {memo}\nApprovals needed: {threshold} of {owner_count}\nExpires: {}\nRequest: {consilium_id}\n\nReview and approve: {approval_url}\n\nYour code: {code}\n\nOpening the link alone approves nothing. Check the destination address against the one you expect before you enter the code — an approved payout cannot be recalled.\n\n—\n{FOOTER_SECURITY}\n",
			hash_prefix(payload_hash),
			fmt_ts(expires_at)
		),
	}
}

/// What the owners are told after a payout request was decided, executed or failed.
pub fn payout_outcome(consilium_id: &str, outcome: &str, network: &str, address: &str, amount: &str, detail: &str) -> RenderedEmail {
	let headline = format!("Payout {}", outcome.to_lowercase());
	let mut inner = String::new();
	inner.push_str(&eyebrow("Treasury"));
	inner.push_str(&heading(&headline));
	inner.push_str(&detail_box(&[
		("Outcome", outcome.to_owned()),
		("Amount", amount.to_owned()),
		("Network", network.to_owned()),
		("Request", consilium_id.to_owned()),
	]));
	inner.push_str(&exact_value("Destination address", address));
	if !detail.is_empty() {
		inner.push_str(&paragraph(detail));
	}
	inner.push_str(&paragraph("This message needs no action from you. It is the record of what the consilium decided."));

	RenderedEmail {
		subject: format!("{headline} — {amount} on {network}"),
		html: shell(&headline, &card(&inner), FOOTER_SECURITY, "", "Treasury"),
		text: format!(
			"{headline}\n\nOutcome: {outcome}\nAmount: {amount}\nNetwork: {network}\nDestination address: {address}\nRequest: {consilium_id}\n\n{detail}\n\n—\n{FOOTER_SECURITY}\n"
		),
	}
}

// ── building blocks ────────────────────────────────────────────────────────

/// Why a governance mail has no unsubscribe link, said out loud.
const FOOTER_SECURITY: &str =
	"You are receiving this because you hold an owner seat. Security mail cannot be switched off — if it could, muting it would be the first thing an attacker did.";

/// A value that must be read EXACTLY: rendered in full, monospace, and allowed to wrap
/// rather than truncate. A `0x1234…abcd` in an approval mail is an invitation to
/// approve the wrong address.
fn exact_value(label: &str, value: &str) -> String {
	format!(
		r#"<p style="margin:0 0 4px;font-family:{SANS};font-size:11px;line-height:15px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;color:{MUTED};">{}</p><p style="margin:0 0 14px;padding:12px 14px;background:{BLACK};border:1px solid {HAIR};border-radius:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;line-height:20px;word-break:break-all;color:{MIST};">{}</p>"#,
		esc(label),
		esc(value)
	)
}

/// The secret code, set apart from the link on purpose. The link proves nothing — mail
/// gateways follow it automatically — and this is the part only a person who opened the
/// message can supply.
fn code_panel(code: &str) -> String {
	format!(
		r#"<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:16px 0 14px;background:{BLACK};border:1px solid {TEAL};border-radius:10px;"><tr><td align="center" style="padding:18px;"><p style="margin:0 0 6px;font-family:{SANS};font-size:11px;line-height:15px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;color:{MUTED};">Type this code on that page</p><p style="margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:26px;line-height:34px;font-weight:700;letter-spacing:5px;color:{TEAL};">{}</p></td></tr></table>"#,
		esc(code)
	)
}

/// Enough of the hash to bind an approval to one payload, without a wall of hex. The
/// DESTINATION is never abbreviated this way — only the hash is.
fn hash_prefix(hash: &str) -> String {
	if hash.chars().count() > 16 {
		format!("{}…", hash.chars().take(16).collect::<String>())
	} else {
		hash.to_owned()
	}
}

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
	let topic = esc(topic_label);
	// A security mail deliberately passes an empty target: there is no opting out of
	// being told that your own seat, or the fund's money, is being voted on.
	let unsub = if unsubscribe_url.is_empty() {
		String::new()
	} else {
		format!(
			r#"<p style="margin:0;font-family:{SANS};font-size:12px;line-height:16px;font-weight:500;color:{TEAL};"><a href="{}" style="color:{TEAL};text-decoration:none;">Unsubscribe from this topic</a></p>"#,
			esc(unsubscribe_url)
		)
	};
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
{unsub}
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

	const LONG_ADDRESS: &str = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

	fn approval() -> RenderedEmail {
		payout_approval(
			"c-1",
			"ada@example.com",
			"Ethereum",
			LONG_ADDRESS,
			"12,500.00 USDT",
			"Q3 revenue <sweep>",
			"9f2c1ab34d5e6f708192a3b4c5d6e7f8",
			3,
			5,
			1_785_143_640,
			"https://evinvest.ltd/approve/tok",
			"H7K2M9PQRS",
		)
	}

	#[test]
	fn the_removal_invitation_separates_the_code_from_the_link() {
		let mail = owner_removal_self_accept(
			"ada@example.com",
			"Repeated <policy> breaches",
			"https://evinvest.ltd/governance/removal/tok",
			"H7K2M9PQRS",
			1_785_143_640,
		);
		assert!(mail.html.contains("https://evinvest.ltd/governance/removal/tok"), "the target cannot answer without the page");
		assert!(mail.html.contains("H7K2M9PQRS") && mail.text.contains("H7K2M9PQRS"), "the code reaches both alternatives");
		// Pitfall 5: someone who thinks the click decided it never comes back to finish.
		for part in [&mail.html, &mail.text] {
			assert!(part.contains("link alone does nothing"), "the mail must say plainly that a click decides nothing");
		}
		assert!(mail.html.contains("&lt;policy&gt;"), "the initiator's free text is escaped — it is not markup");
		assert!(!mail.html.contains("Unsubscribe"), "there is no opting out of being told your own seat is being voted on");
	}

	/// Pitfall 13. A `0x1234…abcd` in an approval mail is an invitation to approve the
	/// wrong address, so the destination is rendered whole in both alternatives.
	#[test]
	fn the_payout_address_is_never_truncated() {
		let mail = approval();
		assert!(mail.html.contains(LONG_ADDRESS), "the full destination must survive into the HTML");
		assert!(mail.text.contains(LONG_ADDRESS), "and into the plain-text alternative");
		assert!(!mail.html.contains("…0f44e"), "no ellipsis anywhere near the address");
	}

	#[test]
	fn the_payout_mail_shows_everything_an_owner_is_agreeing_to() {
		let mail = approval();
		for expected in ["12,500.00 USDT", "Ethereum", "ada@example.com", "3 of 5", "H7K2M9PQRS", "https://evinvest.ltd/approve/tok"] {
			assert!(mail.html.contains(expected), "the approval page must show {expected}");
		}
		assert!(
			mail.html.contains("9f2c1ab34d5e6f70…"),
			"the payload hash is shown as a prefix — enough to bind, not a wall of hex"
		);
		assert!(mail.html.contains("&lt;sweep&gt;"), "the memo is escaped");
		assert!(mail.subject.contains("12,500.00 USDT"), "the subject alone tells an owner what is being asked");
	}

	#[test]
	fn the_outcome_mail_is_a_record_and_asks_for_nothing() {
		let mail = payout_outcome("c-1", "EXECUTED", "Ethereum", LONG_ADDRESS, "12,500.00 USDT", "Broadcast at block 21000000.");
		assert!(mail.html.contains(LONG_ADDRESS), "the destination is shown in full here too");
		assert!(mail.html.contains("needs no action"), "nobody should hunt for a button that is not there");
		assert!(!mail.html.contains("Type this code"), "an outcome carries no secret");
	}

	#[test]
	fn a_hash_shorter_than_the_prefix_is_left_alone() {
		assert_eq!(hash_prefix("abc"), "abc");
		assert_eq!(hash_prefix(&"a".repeat(16)), "a".repeat(16));
		assert_eq!(hash_prefix(&"a".repeat(17)), format!("{}…", "a".repeat(16)));
	}

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
