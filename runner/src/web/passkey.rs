//! Passkeys (WebAuthn): a signed-in account registers one, and anybody signs in with one
//! without naming an account first — the authenticator offers its discoverable credential,
//! whose user handle is the account id. Phishing-resistant and not guessable, so the
//! sign-in ceremony carries no Turnstile token; the `Origin` check still runs, and the
//! WebAuthn verifier pins the origin and the relying-party id on its own.
//!
//! A ceremony is two requests, so its state is kept here between them, keyed by an opaque
//! id the browser echoes. In process, like the OAuth transaction (`oauth::OAuthTxStore`):
//! a ceremony that lands on another replica fails and is simply begun again.

use std::{collections::HashMap, time::Duration};

use axum::{Json, extract::State, http::HeaderMap};
use axum_extra::extract::cookie::CookieJar;
use domain::users::UserId;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use webauthn_rs::prelude::{DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential};

use crate::{
	ports::PasskeyRow,
	web::{
		WebState, now_secs, random_token,
		sign_in::{Answered, Refusal, guard, internal, signed_in, signed_in_as},
	},
};

/// How long a ceremony may take between its two requests: the authenticator's own timeout.
const CEREMONY_TTL: Duration = webauthn_rs::DEFAULT_AUTHENTICATOR_TIMEOUT;
/// The unauthenticated sign-in route feeds this store; the cap bounds it whatever the rate.
const MAX_CEREMONIES: usize = 10_000;

pub struct Ceremonies<T> {
	open: Mutex<HashMap<String, (T, i64)>>,
}

impl<T> Default for Ceremonies<T> {
	fn default() -> Self {
		Self { open: Mutex::new(HashMap::new()) }
	}
}

impl<T> Ceremonies<T> {
	async fn put(&self, state: T) -> String {
		let id = random_token(24);
		let now = now_secs();
		let mut open = self.open.lock().await;
		open.retain(|_, (_, at)| now - *at <= CEREMONY_TTL.as_secs() as i64);
		if open.len() >= MAX_CEREMONIES
			&& let Some(oldest) = open.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| k.clone())
		{
			open.remove(&oldest);
		}
		open.insert(id.clone(), (state, now));
		id
	}

	async fn take(&self, id: &str) -> Option<T> {
		let (state, at) = self.open.lock().await.remove(id)?;
		(now_secs() - at <= CEREMONY_TTL.as_secs() as i64).then_some(state)
	}
}

fn base64url(bytes: &[u8]) -> String {
	use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
	URL_SAFE_NO_PAD.encode(bytes)
}

fn expired() -> Refusal {
	Refusal::new(axum::http::StatusCode::BAD_REQUEST, "passkey_expired")
}

fn rejected() -> Refusal {
	Refusal::new(axum::http::StatusCode::UNAUTHORIZED, "passkey_rejected")
}

/// `POST /auth/passkey/register/options` — begin registering a passkey for the signed-in
/// account. Asks for a discoverable credential, which is what lets it sign in without an
/// account named first.
pub async fn register_options(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let user = st.users.find_by_id(id).await.map_err(|e| internal("passkey: account not read", e))?.ok_or(rejected())?;
		let existing = st.credentials.passkeys(id).await.map_err(|e| internal("passkey: credentials not read", e))?;
		let exclude = existing
			.iter()
			.map(|row| serde_json::from_value::<Passkey>(row.passkey.clone()).map(|p| p.cred_id().clone()))
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| internal("passkey: a stored passkey does not parse", e))?;
		let label = user.username().map_or(user.email().as_str(), |u| u.as_str());
		let (options, state) = st
			.webauthn
			.start_passkey_registration(id.raw(), user.email().as_str(), label, Some(exclude))
			.map_err(|e| internal("passkey: registration not begun", e))?;
		let mut options = serde_json::to_value(options).map_err(|e| internal("passkey: options not serialized", e))?;
		// The verifier asks for no resident key; a passkey that cannot be discovered could only
		// sign in to an account named first, which this flow never does.
		options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
		options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(true);
		let ceremony = st.passkey_registrations.put((id, state)).await;
		Ok(Json(json!({ "ceremony": ceremony, "options": options })))
	}
	.await;
	Ok((jar, answer))
}

#[derive(Deserialize)]
pub struct RegisterVerify {
	ceremony: String,
	credential: RegisterPublicKeyCredential,
	/// The reader's own label for it.
	name: String,
}

/// `POST /auth/passkey/register/verify` — finish registering, and keep the passkey.
pub async fn register_verify(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<RegisterVerify>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = async {
		let name = body.name.trim();
		if name.is_empty() || name.chars().count() > 64 {
			return Err(Refusal::new(axum::http::StatusCode::BAD_REQUEST, "invalid_name"));
		}
		let (owner, state): (UserId, PasskeyRegistration) = st.passkey_registrations.take(&body.ceremony).await.ok_or_else(expired)?;
		if owner != id {
			return Err(expired());
		}
		let passkey = st.webauthn.finish_passkey_registration(&body.credential, &state).map_err(|e| {
			tracing::info!(error = %e, "passkey: registration refused");
			rejected()
		})?;
		let row = PasskeyRow {
			credential_id: base64url(passkey.cred_id()),
			passkey: serde_json::to_value(&passkey).map_err(|e| internal("passkey: not serialized", e))?,
			name: name.to_owned(),
			created_at: now_secs(),
			last_used_at: None,
		};
		match st.credentials.add_passkey(id, row).await.map_err(|e| internal("passkey: not stored", e))? {
			true => Ok(Json(json!({ "ok": true }))),
			false => Err(Refusal::new(axum::http::StatusCode::CONFLICT, "passkey_registered")),
		}
	}
	.await;
	Ok((jar, answer))
}

/// `POST /auth/passkey/signin/options` — begin a sign-in nobody is named in.
pub async fn signin_options(State(st): State<WebState>, headers: HeaderMap) -> Result<Json<Value>, Refusal> {
	let st = &st.inner;
	guard(st, &headers, None).await?;
	let (options, state) = st.webauthn.start_discoverable_authentication().map_err(|e| internal("passkey: sign-in not begun", e))?;
	let ceremony = st.passkey_sign_ins.put(state).await;
	Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

#[derive(Deserialize)]
pub struct SigninVerify {
	ceremony: String,
	credential: PublicKeyCredential,
}

/// `POST /auth/passkey/signin/verify` — the authenticator named the account (its user handle
/// is the account id); check the assertion against that account's passkey and sign in.
pub async fn signin_verify(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<SigninVerify>) -> Result<(CookieJar, Json<Value>), Refusal> {
	let st = &st.inner;
	guard(st, &headers, None).await?;
	let state: DiscoverableAuthentication = st.passkey_sign_ins.take(&body.ceremony).await.ok_or_else(expired)?;
	let (account, credential_id) = st.webauthn.identify_discoverable_authentication(&body.credential).map_err(|e| {
		tracing::info!(error = %e, "passkey: assertion names no account");
		rejected()
	})?;
	let account = UserId::from_raw(account);
	let credential_id = base64url(credential_id);
	let stored = st.credentials.passkeys(account).await.map_err(|e| internal("passkey: credentials not read", e))?;
	let row = stored.into_iter().find(|row| row.credential_id == credential_id).ok_or_else(rejected)?;
	let mut passkey: Passkey = serde_json::from_value(row.passkey).map_err(|e| internal("passkey: a stored passkey does not parse", e))?;
	let result = st
		.webauthn
		.finish_discoverable_authentication(&body.credential, state, &[DiscoverableKey::from(&passkey)])
		.map_err(|e| {
			tracing::info!(error = %e, "passkey: assertion refused");
			rejected()
		})?;
	passkey.update_credential(&result);
	let updated = serde_json::to_value(&passkey).map_err(|e| internal("passkey: not serialized", e))?;
	st.credentials
		.passkey_used(&credential_id, updated, now_secs())
		.await
		.map_err(|e| internal("passkey: use not recorded", e))?;
	signed_in_as(st, jar, &headers, account).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Remove {
	credential_id: String,
}

/// `POST /auth/passkey/remove` — forget one of the signed-in account's passkeys.
pub async fn remove(State(st): State<WebState>, jar: CookieJar, headers: HeaderMap, Json(body): Json<Remove>) -> Answered {
	let st = &st.inner;
	let caller = signed_in(st, &jar, &headers).await?;
	let id = caller.id;
	let jar = caller.refreshed(st, jar);
	let answer = match st.credentials.remove_passkey(id, &body.credential_id).await {
		Ok(true) => Ok(Json(json!({ "ok": true }))),
		Ok(false) => Err(Refusal::new(axum::http::StatusCode::NOT_FOUND, "passkey_unknown")),
		Err(e) => Err(internal("passkey: not removed", e)),
	};
	Ok((jar, answer))
}
