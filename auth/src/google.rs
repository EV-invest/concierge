//! Google OAuth2 confidential-client flow (the only outbound HTTP this plane makes).
//!
//! The auth service exchanges the browser's authorization code (with its PKCE
//! verifier) for Google's tokens, verifies the returned `id_token` against
//! Google's JWKS, checks the `nonce`, and extracts the stable `sub` + verified
//! email. Google's token is then **discarded** — it is never forwarded inward; the
//! plane mints its own first-party token instead, and the plane's `sub` is the
//! concierge user id, never Google's `sub`.

use std::{
	collections::HashMap,
	sync::Mutex,
	time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;

use crate::{AuthError, config::GoogleConfig};

const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const CERTS_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

/// Floor on how often the certs endpoint may be re-fetched, so a flood of
/// unknown-`kid` id_tokens cannot amplify into a DoS against Google (mirroring the
/// plane verifier's [`MIN_REFRESH_INTERVAL`](crate::verifier)). A refresh also waits
/// out the `Cache-Control: max-age` the last response advertised.
const MIN_CERTS_REFRESH: Duration = Duration::from_secs(30);

/// The verified identity extracted from a Google `id_token`.
#[derive(Clone, Debug)]
pub struct GoogleIdentity {
	pub subject: String,
	pub email: String,
	pub email_verified: bool,
}

/// A configured Google OAuth2 client.
pub struct GoogleOauth {
	client_id: String,
	client_secret: String,
	http: reqwest::Client,
	token_endpoint: String,
	certs_endpoint: String,
	certs: Mutex<CertCache>,
}
impl GoogleOauth {
	pub fn new(config: &GoogleConfig) -> Self {
		Self {
			client_id: config.client_id.clone(),
			client_secret: config.client_secret.clone(),
			http: reqwest::Client::new(),
			token_endpoint: TOKEN_ENDPOINT.to_string(),
			certs_endpoint: CERTS_ENDPOINT.to_string(),
			certs: Mutex::new(CertCache::default()),
		}
	}

	/// Exchange an authorization code for Google's tokens and return the verified
	/// identity. `nonce` must equal the one the BFF placed in the authorize request.
	pub async fn exchange_code(&self, auth_code: &str, code_verifier: &str, redirect_uri: &str, nonce: &str) -> Result<GoogleIdentity, AuthError> {
		let response = self
			.http
			.post(&self.token_endpoint)
			.form(&[
				("code", auth_code),
				("client_id", &self.client_id),
				("client_secret", &self.client_secret),
				("redirect_uri", redirect_uri),
				("grant_type", "authorization_code"),
				("code_verifier", code_verifier),
			])
			.send()
			.await
			.map_err(|e| AuthError::ProviderUnavailable(format!("google token request failed: {e}")))?;

		// Only a 400 is Google REJECTING the grant (invalid_grant/invalid_request: bad or
		// expired code, PKCE mismatch) — the caller's problem. Every other non-success —
		// 401/403 (our deployed client credentials), 429, 5xx — is Google or our
		// deployment failing: an incident the caller cannot fix by re-authenticating.
		let status = response.status();
		if !status.is_success() {
			let msg = format!("google token endpoint returned {status}");
			return Err(if status == reqwest::StatusCode::BAD_REQUEST {
				AuthError::Provider(msg)
			} else {
				AuthError::ProviderUnavailable(msg)
			});
		}

		let token: GoogleTokenResponse = response
			.json()
			.await
			.map_err(|e| AuthError::ProviderUnavailable(format!("malformed google token response: {e}")))?;
		let id_token = token.id_token.ok_or_else(|| AuthError::ProviderUnavailable("google response had no id_token".into()))?;

		self.verify_id_token(&id_token, nonce).await
	}

	async fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<GoogleIdentity, AuthError> {
		let header = decode_header(id_token).map_err(|_| AuthError::Provider("malformed google id_token header".into()))?;
		if header.alg != Algorithm::RS256 {
			return Err(AuthError::Provider("unexpected google id_token algorithm".into()));
		}
		let kid = header.kid.ok_or_else(|| AuthError::Provider("google id_token missing kid".into()))?;

		let key = match self.cached_key(&kid) {
			Some(key) => key,
			None => {
				self.refresh_certs().await?;
				self.cached_key(&kid).ok_or_else(|| AuthError::Provider("no matching google signing key".into()))?
			}
		};

		let mut validation = Validation::new(Algorithm::RS256);
		validation.set_audience(&[&self.client_id]);
		validation.set_issuer(&ISSUERS);
		validation.set_required_spec_claims(&["exp", "aud", "iss"]);

		let data = decode::<GoogleIdClaims>(id_token, &key, &validation).map_err(|e| AuthError::Provider(format!("google id_token rejected: {e}")))?;
		let claims = data.claims;

		if claims.nonce.as_deref() != Some(nonce) {
			return Err(AuthError::Provider("google id_token nonce mismatch".into()));
		}
		let email = claims.email.ok_or_else(|| AuthError::Provider("google id_token had no email".into()))?;

		Ok(GoogleIdentity {
			subject: claims.sub,
			email,
			email_verified: claims.email_verified.unwrap_or(false),
		})
	}

	fn cached_key(&self, kid: &str) -> Option<DecodingKey> {
		self.certs.lock().unwrap_or_else(|e| e.into_inner()).keys.get(kid).cloned()
	}

	/// Re-fetch Google's certs, honoring the `Cache-Control: max-age` window of the
	/// previous response (and never more often than [`MIN_CERTS_REFRESH`]) so a flood
	/// of unknown-`kid` id_tokens cannot amplify into a DoS against Google. The cache
	/// is held under a `Mutex` (not across the await): whoever loses the race re-reads
	/// the now-fresh `refresh_after` and skips the redundant call.
	async fn refresh_certs(&self) -> Result<(), AuthError> {
		{
			let mut cache = self.certs.lock().unwrap_or_else(|e| e.into_inner());
			if let Some(at) = cache.refresh_after
				&& Instant::now() < at
			{
				return Ok(());
			}
			// Stamp the ATTEMPT, not just the success (mirroring the plane verifier):
			// otherwise a failing certs endpoint is re-hit — and, since failures are
			// operational incidents that alert, re-reported — on every login of an outage.
			cache.refresh_after = Some(Instant::now() + MIN_CERTS_REFRESH);
		}

		let response = self
			.http
			.get(&self.certs_endpoint)
			.send()
			.await
			.map_err(|e| AuthError::ProviderUnavailable(format!("google certs request failed: {e}")))?;
		let max_age = max_age_of(response.headers());
		let certs: JwkSet = response.json().await.map_err(|e| AuthError::ProviderUnavailable(format!("malformed google certs: {e}")))?;

		let mut keys = HashMap::new();
		for jwk in &certs.keys {
			let Some(kid) = jwk.common.key_id.clone() else { continue };
			let key = DecodingKey::from_jwk(jwk).map_err(|e| AuthError::ProviderUnavailable(format!("bad google jwk: {e}")))?;
			keys.insert(kid, key);
		}

		let mut cache = self.certs.lock().unwrap_or_else(|e| e.into_inner());
		cache.keys = keys;
		cache.refresh_after = Some(Instant::now() + max_age.max(MIN_CERTS_REFRESH));
		Ok(())
	}
}

/// Google's signing keys (by `kid`) with the freshness window from the last fetch.
#[derive(Default)]
struct CertCache {
	keys: HashMap<String, DecodingKey>,
	/// When the cached keys may next be refreshed: the later of the response's
	/// `Cache-Control: max-age` expiry and [`MIN_CERTS_REFRESH`]. `None` until the
	/// first fetch.
	refresh_after: Option<Instant>,
}

/// Parse the `max-age` directive from a `Cache-Control` response header, returning
/// zero when absent or unparseable (so freshness then falls back to [`MIN_CERTS_REFRESH`]).
fn max_age_of(headers: &reqwest::header::HeaderMap) -> Duration {
	headers
		.get(reqwest::header::CACHE_CONTROL)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.split(',').filter_map(|d| d.trim().strip_prefix("max-age=")).find_map(|s| s.parse::<u64>().ok()))
		.map(Duration::from_secs)
		.unwrap_or_default()
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
	id_token: Option<String>,
}

#[derive(Deserialize)]
struct GoogleIdClaims {
	sub: String,
	#[serde(default)]
	email: Option<String>,
	#[serde(default)]
	email_verified: Option<bool>,
	#[serde(default)]
	nonce: Option<String>,
}

#[cfg(test)]
mod tests {
	use std::{
		io::{Read, Write},
		net::{SocketAddr, TcpListener},
		sync::{
			Arc, Mutex,
			atomic::{AtomicUsize, Ordering},
		},
	};

	use jsonwebtoken::{EncodingKey, Header, encode, get_current_timestamp};
	use serde::Serialize;

	use super::*;

	#[test]
	fn parses_max_age_from_cache_control() {
		let mut headers = reqwest::header::HeaderMap::new();
		headers.insert(reqwest::header::CACHE_CONTROL, "public, max-age=3600, must-revalidate".parse().unwrap());
		assert_eq!(max_age_of(&headers), Duration::from_secs(3600));

		let empty = reqwest::header::HeaderMap::new();
		assert_eq!(max_age_of(&empty), Duration::ZERO);
	}

	/// Serve a canned response with the given status line from a local socket (with the
	/// `Cache-Control: max-age` the real endpoints send), counting inbound connections
	/// so a test can assert how often the endpoint was actually hit.
	fn serve(status: &'static str, body: String) -> (SocketAddr, Arc<AtomicUsize>) {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap();
		let hits = Arc::new(AtomicUsize::new(0));
		let counter = Arc::clone(&hits);
		std::thread::spawn(move || {
			for stream in listener.incoming() {
				let mut stream = stream.unwrap();
				let mut buf = [0u8; 2048];
				let _ = stream.read(&mut buf);
				counter.fetch_add(1, Ordering::SeqCst);
				let resp = format!(
					"HTTP/1.1 {status}\r\nCache-Control: max-age=3600\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
					body.len()
				);
				let _ = stream.write_all(resp.as_bytes());
			}
		});
		(addr, hits)
	}

	/// A second refresh inside the cache window must not hit the certs endpoint again,
	/// so each login no longer round-trips Google.
	#[tokio::test]
	async fn refresh_is_throttled_within_cache_window() {
		let (addr, hits) = serve("200 OK", r#"{"keys":[]}"#.into());
		let google = google_at(TOKEN_ENDPOINT.into(), format!("http://{addr}/certs"));

		google.refresh_certs().await.unwrap();
		google.refresh_certs().await.unwrap();

		assert_eq!(hits.load(Ordering::SeqCst), 1, "second refresh within the window must reuse the cache");
	}

	// A throwaway RSA-2048 keypair for exercising `verify_id_token`, generated with
	// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`; the public
	// modulus (JWK `n`, `e` = AQAB) is precomputed so the test JWKS needs no RSA
	// dependency.
	const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOOeT0L7CsVClj
ny8j4ke4aCFs+TNYnhA6UkxLnfUaHDrvvqgtgLUwyTXYHGlG1m02UaV7NLYDthu5
+mbYIirVzWqqrnNME2L3gPOyFAI2kuZtmxO5HfLmQNLk6Qts4Sin+mgC6A2aBxqP
lEv6y7tSPe+G08IAn45AIdD4KbBvZGUL2wdDqr4eCoFkkh/2tSFcorsFtjvaECCN
ZFKBWVAIGFdW4X7uy++9bZShYtXVQvWuckv+yV4OIhGSjXxosHzM1xhBek+VRo1X
KZeKxEOancBwjH8wMuDC+OXxLq+u/VHhDqJ4/9Rmx+4AtTAMV8lNxxtu0bwzVhgm
OM8mBngrAgMBAAECggEADIqiZrDfyOf1YtGZ4RzJyWhlYAABV2Pr2+zu87C16NIx
419wHhRNvWgyYuPKozw3Hntb2cccd21QkloTSkgJqUCTOn4Re11Sdd4QJyxNIvSC
fvftyYkNh8mf1ojPR3fWxe08lhcQSX9VGWMNAkH3/ZbQRYRrSY5qhqWH1KlayYTw
vw0ym3tPLvaw4UOv/pmVKOVQxcj8dabFSpqcWAnGWnwbM+wFGrfub0bvq74udXbA
rSSsdoAksVG1kkSPz7uGHxhcyVRzApt+rZ3VZwhZjHaOB44yKf0zGsGoTy3nkM2k
Es953aqjiBwDmQL8y+g3FigMyMOQY5FKODy2IK/hgQKBgQDrLH6Wl3x88aPX2E21
LVHG8wI2TJo6TwfqOZad5TOq79HlcukXVeALUR797kmdNfgP3LI9jjs6W+s87wZo
CX8Oc3YCm8Rp3QIdfBKohoe7dEFR53D/Rah5v7LF0DDEmyRiidkJZUxeSLNiFw7I
OFvfGrgVEEmtj4+/cbTBNdu8KQKBgQDgfSRtPM8fut+8QUKW1LG7EA7jlg385zb9
M6SP9NsI0QAX3Lk87RMt2gdVeWCBQIMhLPmBIfLavQFBhmjVnKQN/PvP9p0oyVIF
1B6nLRPmfeoYH+hqUpWwMBWGIC6BnaLFLQ0dUeVUpLz0NbAanbU47E4+vNoYqgnn
3k8hUr+cMwKBgQDZhNEdZsZNJo+eEEJnxqAx/QjZwmaQchLnERb/ukTc4W7p5Cw2
WkadEQ4yXtmV4JotybrO9qRPqT9en9L0HXx4mFDZvsugAzx2mxEC8VPQDYpxQDmi
0wIugiHPl23UG48+2TN23kwRlPreSmdwx7gqFqOXT/Zl4zhZIcnHP5KbaQKBgACD
iM/PMdIqxVRS+eoKdpWtBbuznjiT9uZBdgD2WIH+qHdlg+8Fw+N4+kdRzcy97w7m
YXPQNhQWFqilvBuxDhcSGylwsQ9k1pE42REc40zFwQFpIUkNA1ax5Xq3HCQjzjmR
TtRgWZwF/IC6lrqY3c9RiyRNnlosGXW0Zo32+IVNAoGACwiyaGHEuo6faLPBdRA7
2NSEFEn7E2u66sO/0zR7MFMCRGxwW98sMz7N+8Qape4Ih6E1ym7BxhAnzeSM0Ksj
LpH611KSWYWbHz7VnuC87LrzqdOXDJG5jpTjnWXejGrb/w8vIxuSgUAP2wUNuSEA
JVo7HVcH1N/2KX+Xqrzf6AU=
-----END PRIVATE KEY-----
";
	const TEST_RSA_JWK_N: &str = "zjnk9C-wrFQpY58vI-JHuGghbPkzWJ4QOlJMS531Ghw6776oLYC1MMk12BxpRtZtNlGlezS2A7Ybufpm2CIq1c1qqq5zTBNi94DzshQCNpLmbZsTuR3y5kDS5OkLbOEop_poAugNmgcaj5RL-su7Uj3vhtPCAJ-OQCHQ-Cmwb2RlC9sHQ6q-HgqBZJIf9rUhXKK7BbY72hAgjWRSgVlQCBhXVuF-7svvvW2UoWLV1UL1rnJL_sleDiIRko18aLB8zNcYQXpPlUaNVymXisRDmp3AcIx_MDLgwvjl8S6vrv1R4Q6ieP_UZsfuALUwDFfJTccbbtG8M1YYJjjPJgZ4Kw";
	const TEST_KID: &str = "google-test-kid";

	// A second throwaway RSA key that is NOT in the served JWKS — its signatures must
	// fail verification even under the known `kid`.
	const ROGUE_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD3v7anKVU7C20q
A7HQRZuz9jQL/baBiBG7P59olyA7MSWERLnbWC0G/jSMri/xLwhOdr+v08E5wLcs
fcClGaFnhavQKV9gRQO5yzQY9lhJTkiHNaXq8uVjlkzMdd6t2H3N3rwVC35BoFXX
gzpsVy5qn4rNdny28cQcOpt1UrocnMRRN4E1LBQD8g+fpzmRFsTYawf5tlIczXhS
N4cwESoDXAxEOqnK09I+143Q6fVqikyJf7LoGNWaNUv0CqnbG7l/21gUSZni5rL3
5PJWWH7Ol6ap/x77nODa8n7guaKe0S+gBK1SY/C/s9s3yv9YUGTkv5cPrAn07MSh
04FmDANrAgMBAAECggEAXzRoe+9ZxeFbt2AJFjiRn4P2tz7twfQooDTQTNB6fdSi
jqQcaeqGDyBj0EXlvYCt5/0hJ2+v2sIwgePnQmrJiC8pecpUUPnkdyLb59XO0ojH
PVJD6rghp3XsGEwZYOQHYDP+QfYTNCPpqPJQYq7T8vxRSiiEv4bDrndlIx5Bz9k6
1XzdbUHNS6w2mgYArvSnHIYA8T1GzR7PvTMyyUb5ZjTsZqUkPiRiWfXizZYkyR1j
ZEKSysJOTpjSjU3k7JPcO75S9Byc9Iea5WeGR0Yy5RCuSS9oGG0UI/cLzW1T2UcC
m18KzDvPrJT7+yC2u2qX17QqNmPZtmb/vX8lL36wEQKBgQD99l2oSV69E3/085Z8
TQ8qdxxdTxe2aWc1yjYUFx4oMYFlc/Kw18CSm6OyNnT+iG9sdk+pbdy5Ocb/Sqiy
nnjLDrtiVn0l5L6mcAn9/RBeKSwku4AGKl4EYoI+ogDkAUHBGseM/4rRXqc0Dwzk
a3I7Qjbx23llEOkic7ymkJj5UQKBgQD5vJXS+8d1aLZuL2qOFI+W6XyEI4O5+7os
WeXfRLOm7X6XYzXf9grFY9JNQ2zDNkTuzr35qEqVycjVFafRNHIXMTeOUYVEXQKn
GWx5efuUEmsVBn55Wc9xMaHk3f7VnNhXWw12AF+Z5MVPNJu1Uy9rO0m4SHNvRd2A
0t1j7CJB+wKBgQCfn4IujC8n2GHMrG4hoq2tm0AQxe25kXZ1sKtc5UrnKHaUNdSM
oo8/luPE18WhVk/ydEqNy6e4JECXpW1zF3gE6TWOEZ6Hesb6BeHB6pWnGWnNjKxj
M630Q5Zpl5nHtaKGpTZXwSaXgk7Fwc/wojgiVvQCAFjE1WQza1tftfLwgQKBgBpv
LMi1X+p8l/rXyAacBIrr0gNGoxXXoGA7b8qPQhjkQKcTmEtJhuBX7ZXCEkwjfW5t
scwwVRy/zCNJ9IZ/b6gmzIOi+2E+Gx7G4SWGlOuae30xP8fmir+nikRofyXrQTcV
6znXVkc64Ou+XND3qihGkUoRWS6pDYYqS8bc4s9rAoGBAL/HaoF+9qfExwAettFa
FIQxCyu41U1+mnWSkGSpelruZp9C9KksfyJuGfSyM7JpeUaRjZmWGU6NuNw5HCV2
iTjbqCev5bkRC+SGrObajKjwRttvaFRG31VPG3nD8G3GUQblaJ3OaVICCYq9eFJ1
vDYvLc+HvAu+fITPD3S9Dvg0
-----END PRIVATE KEY-----
";

	const CLIENT_ID: &str = "ev-client-id";
	const NONCE: &str = "nonce-123";

	fn jwks_body() -> String {
		format!(r#"{{"keys":[{{"kty":"RSA","alg":"RS256","use":"sig","kid":"{TEST_KID}","n":"{TEST_RSA_JWK_N}","e":"AQAB"}}]}}"#)
	}

	fn google() -> GoogleOauth {
		google_with_cache(CertCache::default()).0
	}

	fn google_at(token_endpoint: String, certs_endpoint: String) -> GoogleOauth {
		GoogleOauth {
			client_id: CLIENT_ID.into(),
			client_secret: "secret".into(),
			http: reqwest::Client::new(),
			token_endpoint,
			certs_endpoint,
			certs: Mutex::new(CertCache::default()),
		}
	}

	fn google_with_cache(cache: CertCache) -> (GoogleOauth, Arc<AtomicUsize>) {
		let (addr, hits) = serve("200 OK", jwks_body());
		let google = GoogleOauth {
			certs: Mutex::new(cache),
			..google_at(TOKEN_ENDPOINT.into(), format!("http://{addr}/certs"))
		};
		(google, hits)
	}

	/// Every rejection in `verify_id_token` maps to `AuthError::Provider`, so a bare
	/// `is_err` cannot tell WHICH check fired — a broken fixture (certs fetch failing,
	/// now `ProviderUnavailable`) would otherwise satisfy every rejection test.
	/// Returning the message lets each test pin its own rejection reason.
	async fn rejection(google: &GoogleOauth, token: &str, nonce: &str) -> String {
		match google.verify_id_token(token, nonce).await {
			Err(AuthError::Provider(msg)) => msg,
			Ok(_) => panic!("id_token was unexpectedly accepted"),
			Err(other) => panic!("unexpected error variant: {other:?}"),
		}
	}

	#[derive(Serialize)]
	struct IdClaims {
		iss: String,
		aud: String,
		sub: String,
		exp: u64,
		iat: u64,
		email: String,
		email_verified: bool,
		nonce: String,
	}

	fn id_claims() -> IdClaims {
		IdClaims {
			iss: ISSUERS[0].into(),
			aud: CLIENT_ID.into(),
			sub: "google-sub-1".into(),
			exp: get_current_timestamp() + 600,
			iat: get_current_timestamp(),
			email: "user@example.com".into(),
			email_verified: true,
			nonce: NONCE.into(),
		}
	}

	fn mint(claims: &IdClaims, pem: &str, kid: &str) -> String {
		let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
		let mut header = Header::new(Algorithm::RS256);
		header.kid = Some(kid.into());
		encode(&header, claims, &key).unwrap()
	}

	#[tokio::test]
	async fn accepts_a_well_formed_id_token() {
		// The accept case proves the harness itself is sound — every rejection below
		// fails on the checked property, not a broken fixture.
		let identity = google().verify_id_token(&mint(&id_claims(), TEST_RSA_PEM, TEST_KID), NONCE).await.unwrap();
		assert_eq!(identity.subject, "google-sub-1");
		assert_eq!(identity.email, "user@example.com");
		assert!(identity.email_verified);
	}

	#[tokio::test]
	async fn rejects_non_rs256_algorithm() {
		// An HS256 token (secret = the public JWK, the classic key-confusion downgrade)
		// must be refused by the explicit alg pin BEFORE any key lookup — the pinned
		// message proves that layer fired, not `decode`'s own algorithm check (which
		// would also reject, letting the pin silently disappear).
		let mut header = Header::new(Algorithm::HS256);
		header.kid = Some(TEST_KID.into());
		let token = encode(&header, &id_claims(), &EncodingKey::from_secret(TEST_RSA_JWK_N.as_bytes())).unwrap();
		let msg = rejection(&google(), &token, NONCE).await;
		assert!(msg.contains("unexpected google id_token algorithm"), "must be refused by the alg pin, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_unsigned_alg_none_token() {
		// An alg-none forgery carrying the FULL valid claims payload and the known kid
		// (header is base64url of `{"alg":"none","kid":"google-test-kid"}`, claims
		// spliced from a well-formed token, empty signature) — so nothing but the
		// missing signature / forbidden algorithm can be the rejection reason.
		let minted = mint(&id_claims(), TEST_RSA_PEM, TEST_KID);
		let claims = minted.split('.').nth(1).unwrap();
		let token = format!("eyJhbGciOiJub25lIiwia2lkIjoiZ29vZ2xlLXRlc3Qta2lkIn0.{claims}.");
		let msg = rejection(&google(), &token, NONCE).await;
		assert!(msg.contains("header") || msg.contains("algorithm"), "must be refused on the header/alg, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_wrong_audience() {
		let mut claims = id_claims();
		claims.aud = "another-client".into();
		let msg = rejection(&google(), &mint(&claims, TEST_RSA_PEM, TEST_KID), NONCE).await;
		assert!(msg.contains("InvalidAudience"), "must be refused on aud, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_wrong_issuer() {
		let mut claims = id_claims();
		claims.iss = "https://accounts.evil.example".into();
		let msg = rejection(&google(), &mint(&claims, TEST_RSA_PEM, TEST_KID), NONCE).await;
		assert!(msg.contains("InvalidIssuer"), "must be refused on iss, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_expired_token() {
		let mut claims = id_claims();
		claims.exp = get_current_timestamp() - 3600;
		let msg = rejection(&google(), &mint(&claims, TEST_RSA_PEM, TEST_KID), NONCE).await;
		assert!(msg.contains("ExpiredSignature"), "must be refused on exp, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_signature_from_a_key_outside_the_jwks() {
		// Signed by the rogue key but stamped with the known kid: the key lookup
		// succeeds and the RSA signature itself must fail.
		let msg = rejection(&google(), &mint(&id_claims(), ROGUE_RSA_PEM, TEST_KID), NONCE).await;
		assert!(msg.contains("InvalidSignature"), "must be refused on the signature, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_unknown_kid_after_refresh() {
		// An unrecognized kid forces a certs refresh; the served JWKS still has no
		// match, so verification must fail rather than fall through.
		let msg = rejection(&google(), &mint(&id_claims(), TEST_RSA_PEM, "no-such-kid"), NONCE).await;
		assert!(msg.contains("no matching google signing key"), "must be refused on the kid, got: {msg}");
	}

	#[tokio::test]
	async fn rejects_nonce_mismatch() {
		let msg = rejection(&google(), &mint(&id_claims(), TEST_RSA_PEM, TEST_KID), "a-different-nonce").await;
		assert!(msg.contains("nonce mismatch"), "must be refused on the nonce, got: {msg}");
	}

	/// A port that refuses connections: bound to reserve it, then dropped.
	fn dead_endpoint() -> SocketAddr {
		TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
	}

	/// A client whose token endpoint answers with the given canned response.
	fn google_with_token_endpoint(status: &'static str, body: &str) -> GoogleOauth {
		let (addr, _) = serve(status, body.into());
		google_at(format!("http://{addr}/token"), CERTS_ENDPOINT.into())
	}

	async fn exchange_failure(google: &GoogleOauth) -> AuthError {
		google.exchange_code("code", "verifier", "https://cb.example", NONCE).await.unwrap_err()
	}

	// A network failure reaching the token endpoint is an incident (UNAVAILABLE +
	// Sentry), NOT a credential rejection — during a partition every login would
	// otherwise read as "user auth failure" with zero telemetry.
	#[tokio::test]
	async fn exchange_transport_failure_is_operational() {
		let google = google_at(format!("http://{}/token", dead_endpoint()), CERTS_ENDPOINT.into());
		let err = exchange_failure(&google).await;
		assert!(matches!(err, AuthError::ProviderUnavailable(_)), "got: {err:?}");
		assert!(err.is_unexpected(), "a transport failure must alert");
	}

	#[tokio::test]
	async fn exchange_google_5xx_is_operational() {
		let err = exchange_failure(&google_with_token_endpoint("503 Service Unavailable", "")).await;
		assert!(matches!(err, AuthError::ProviderUnavailable(_)), "got: {err:?}");
		assert!(err.is_unexpected(), "a Google 5xx must alert");
	}

	// A non-400 4xx is Google failing us, not rejecting the user's grant: rate
	// limiting (429) or broken deployed client credentials (401/403) must alert.
	#[tokio::test]
	async fn exchange_google_429_is_operational() {
		let err = exchange_failure(&google_with_token_endpoint("429 Too Many Requests", "")).await;
		assert!(matches!(err, AuthError::ProviderUnavailable(_)), "got: {err:?}");
		assert!(err.is_unexpected(), "rate limiting by Google must alert");
	}

	#[tokio::test]
	async fn exchange_malformed_token_response_is_operational() {
		let err = exchange_failure(&google_with_token_endpoint("200 OK", "not-json")).await;
		assert!(matches!(err, AuthError::ProviderUnavailable(_)), "got: {err:?}");
	}

	// A 400 is Google REJECTING the grant (bad/expired code, PKCE mismatch): it must
	// stay a quiet UNAUTHENTICATED-class rejection, not page on-call.
	#[tokio::test]
	async fn exchange_google_400_stays_a_rejection() {
		let err = exchange_failure(&google_with_token_endpoint("400 Bad Request", r#"{"error":"invalid_grant"}"#)).await;
		assert!(matches!(err, AuthError::Provider(_)), "got: {err:?}");
		assert!(!err.is_unexpected(), "a rejected grant is not an incident");
	}

	// The certs fetch inside id_token verification is the same class: unreachable
	// certs endpoint → operational failure, not "your token was rejected".
	#[tokio::test]
	async fn certs_transport_failure_is_operational() {
		let google = google_at(TOKEN_ENDPOINT.into(), format!("http://{}/certs", dead_endpoint()));
		let err = google.verify_id_token(&mint(&id_claims(), TEST_RSA_PEM, TEST_KID), NONCE).await.unwrap_err();
		assert!(matches!(err, AuthError::ProviderUnavailable(_)), "got: {err:?}");
		assert!(err.is_unexpected(), "an unreachable certs endpoint must alert");
	}

	// A FAILED certs fetch must stamp the throttle window exactly like a successful
	// one: otherwise every login of a certs outage re-hits the degraded endpoint and
	// re-fires the operational alert, voiding the MIN_CERTS_REFRESH guard.
	#[tokio::test]
	async fn certs_failure_is_throttled_within_the_window() {
		let (addr, hits) = serve("503 Service Unavailable", String::new());
		let google = google_at(TOKEN_ENDPOINT.into(), format!("http://{addr}/certs"));
		let token = mint(&id_claims(), TEST_RSA_PEM, TEST_KID);

		let err = google.verify_id_token(&token, NONCE).await.unwrap_err();
		assert!(matches!(err, AuthError::ProviderUnavailable(_)), "got: {err:?}");

		// Within the window the endpoint is not re-hit; the login fails fast on the
		// (still empty) cache instead of amplifying against the degraded upstream.
		let msg = rejection(&google, &token, NONCE).await;
		assert!(msg.contains("no matching google signing key"), "got: {msg}");
		assert_eq!(hits.load(Ordering::SeqCst), 1, "a failed refresh must still arm the throttle");
	}

	#[tokio::test]
	async fn refreshes_a_warm_cache_when_google_rotates_keys() {
		// A cache already populated by an earlier fetch (whose refresh window has
		// elapsed) must re-fetch when a token arrives under a kid it does not hold —
		// otherwise a Google key rotation strands every login until restart.
		let stale = CertCache {
			keys: HashMap::from([("retired-kid".to_string(), DecodingKey::from_rsa_components(TEST_RSA_JWK_N, "AQAB").unwrap())]),
			refresh_after: Some(Instant::now()),
		};
		let (google, hits) = google_with_cache(stale);
		google.verify_id_token(&mint(&id_claims(), TEST_RSA_PEM, TEST_KID), NONCE).await.unwrap();
		assert_eq!(hits.load(Ordering::SeqCst), 1, "an unknown kid on a warm cache must re-fetch the certs");
	}
}
