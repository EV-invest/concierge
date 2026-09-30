//! The async gRPC authorization layer — the choke point every service mounts.
//!
//! tonic 0.13's `Interceptor` is **synchronous** (`fn call(&mut self, Request<()>)`),
//! so it cannot await JWKS verification. This is therefore a bespoke
//! [`tower::Layer`]: it pulls the bearer token from the request metadata,
//! authenticates it asynchronously via an [`Authenticate`] implementor, injects the
//! verified [`Claims`] into the request extensions on success, and short-circuits
//! with a gRPC `UNAUTHENTICATED` response otherwise.
//!
//! [`Verifier`](crate::verifier::Verifier) is the implementor downstream services
//! plug in. Mount it per service so genuinely public surfaces (e.g. health) stay
//! unauthenticated.

use std::{
	future::Future,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use tonic::body::Body;
use tower::{Layer, Service};

use crate::{AuthError, Claims, clients::BoxFuture};

/// Something that can authenticate a bearer token into [`Claims`].
pub trait Authenticate: Clone + Send + Sync + 'static {
	fn authenticate(&self, token: String) -> impl Future<Output = Result<Claims, AuthError>> + Send;
}

/// A [`tower::Layer`] that authorizes inbound gRPC requests with `A`.
#[derive(Clone)]
pub struct AuthLayer<A> {
	authenticator: A,
	restricted: Option<Restricted>,
}

impl<A> AuthLayer<A> {
	pub fn new(authenticator: A) -> Self {
		Self { authenticator, restricted: None }
	}

	/// Also admit the tokens `authenticator` accepts — but ONLY on the gRPC method
	/// `paths` (`/package.Service/Method`), and only after the primary authenticator
	/// refused them.
	///
	/// This is how a relying party's token (another audience, minted for a client on
	/// another origin) reaches the one read it is for without the primary verifier ever
	/// learning its audience: every other method of every wrapped service still sees
	/// only the primary policy, so it refuses such a token exactly as it refuses a
	/// forged one. The allowlist is by exact method path, never by service, because a
	/// service grows methods and the token must not grow with it.
	pub fn with_restricted<B: Authenticate>(mut self, authenticator: B, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
		let authenticate: RestrictedAuthenticate = Arc::new(move |token| {
			let authenticator = authenticator.clone();
			Box::pin(async move { authenticator.authenticate(token).await })
		});
		self.restricted = Some(Restricted {
			authenticate,
			paths: paths.into_iter().map(Into::into).collect(),
		});
		self
	}
}

/// Inserted into the request extensions beside the [`Claims`] when it was the
/// RESTRICTED authenticator that admitted the caller — a relying party's token, not this
/// plane's. The one handler it reaches uses it to answer with less.
#[derive(Clone, Copy, Debug)]
pub struct RestrictedCaller;

type RestrictedAuthenticate = Arc<dyn Fn(String) -> BoxFuture<'static, Result<Claims, AuthError>> + Send + Sync>;

/// A secondary authenticator and the only method paths it may open.
#[derive(Clone)]
struct Restricted {
	authenticate: RestrictedAuthenticate,
	paths: Arc<[String]>,
}

/// Build the authorization layer for an authenticator (a [`Verifier`] downstream).
///
/// [`Verifier`]: crate::verifier::Verifier
pub fn grpc_auth_layer<A: Authenticate>(authenticator: A) -> AuthLayer<A> {
	AuthLayer::new(authenticator)
}

impl<S, A: Clone> Layer<S> for AuthLayer<A> {
	type Service = GrpcAuth<S, A>;

	fn layer(&self, inner: S) -> Self::Service {
		GrpcAuth {
			inner,
			authenticator: self.authenticator.clone(),
			restricted: self.restricted.clone(),
		}
	}
}

/// The service produced by [`AuthLayer`].
#[derive(Clone)]
pub struct GrpcAuth<S, A> {
	inner: S,
	authenticator: A,
	restricted: Option<Restricted>,
}

impl<S, A, B> Service<http::Request<B>> for GrpcAuth<S, A>
where
	S: Service<http::Request<B>, Response = http::Response<Body>, Error = std::convert::Infallible> + Clone + Send + 'static,
	S::Future: Send + 'static,
	A: Authenticate,
	B: Send + 'static,
{
	type Error = std::convert::Infallible;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
	type Response = http::Response<Body>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
		// Ready-clone: call the instance that was `poll_ready`'d, keep a fresh clone
		// in `self` for the next poll.
		let clone = self.inner.clone();
		let mut inner = std::mem::replace(&mut self.inner, clone);
		let authenticator = self.authenticator.clone();
		// Resolved before the future so the path check never borrows the request body.
		let restricted = self.restricted.as_ref().filter(|r| r.paths.iter().any(|p| p == req.uri().path())).map(|r| r.authenticate.clone());

		Box::pin(async move {
			let Some(token) = bearer_token(req.headers()) else {
				return Ok(status_response(&AuthError::MissingToken));
			};
			let (outcome, via_restricted) = match (authenticator.authenticate(token.clone()).await, restricted) {
				// The primary refusal is what a caller sees when the secondary refuses too:
				// a token that is neither this plane's nor a client's is just an invalid
				// token, and naming the second policy would say which methods have one.
				// Except an outage: "could not decide" must stay retryable, not read as a
				// verdict on the token.
				(Err(primary), Some(secondary)) => match secondary(token).await {
					Ok(claims) => (Ok(claims), true),
					Err(AuthError::Unavailable) => (Err(AuthError::Unavailable), false),
					Err(_) => (Err(primary), false),
				},
				(outcome, _) => (outcome, false),
			};
			match outcome {
				Ok(claims) => {
					req.extensions_mut().insert(claims);
					if via_restricted {
						req.extensions_mut().insert(RestrictedCaller);
					}
					inner.call(req).await
				}
				Err(err) => {
					crate::telemetry::report_unexpected(&err);
					Ok(status_response(&err))
				}
			}
		})
	}
}

// Preserve the wrapped service's gRPC name so the tonic router can dispatch to it.
impl<S: tonic::server::NamedService, A> tonic::server::NamedService for GrpcAuth<S, A> {
	const NAME: &'static str = S::NAME;
}

/// Read the verified [`Claims`] a mounted [`AuthLayer`] injected, from a tonic
/// request. Returns `None` on an unauthenticated path (handler shouldn't trust it).
pub fn claims_of<T>(request: &tonic::Request<T>) -> Option<&Claims> {
	request.extensions().get::<Claims>()
}

fn bearer_token(headers: &http::HeaderMap) -> Option<String> {
	let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
	value.strip_prefix("Bearer ").map(str::to_owned)
}

fn status_response(err: &AuthError) -> http::Response<Body> {
	let status: tonic::Status = err.into();
	// Mirror tonic's own interceptor error path: build the gRPC status response and
	// give it an empty body.
	let (parts, ()) = status.into_http::<()>().into_parts();
	http::Response::from_parts(parts, Body::empty())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::TokenType;

	/// An authenticator with a fixed answer.
	#[derive(Clone)]
	struct Fixed(fn() -> Result<Claims, AuthError>);

	impl Authenticate for Fixed {
		async fn authenticate(&self, _token: String) -> Result<Claims, AuthError> {
			(self.0)()
		}
	}

	fn claims() -> Result<Claims, AuthError> {
		Ok(Claims {
			iss: "iss".into(),
			sub: "user".into(),
			aud: "sa".into(),
			exp: u64::MAX,
			iat: 0,
			typ: TokenType::Access,
			jti: None,
			token_version: 0,
		})
	}

	/// The wrapped service: answers 200 and says whether the caller was marked restricted.
	#[derive(Clone)]
	struct Inner;

	impl Service<http::Request<()>> for Inner {
		type Error = std::convert::Infallible;
		type Future = std::future::Ready<Result<http::Response<Body>, Self::Error>>;
		type Response = http::Response<Body>;

		fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
			Poll::Ready(Ok(()))
		}

		fn call(&mut self, req: http::Request<()>) -> Self::Future {
			let restricted = req.extensions().get::<RestrictedCaller>().is_some();
			std::future::ready(Ok(http::Response::builder().header("x-restricted", restricted.to_string()).body(Body::empty()).unwrap()))
		}
	}

	async fn call(secondary: fn() -> Result<Claims, AuthError>, path: &str) -> http::Response<Body> {
		let layer = AuthLayer::new(Fixed(|| Err(AuthError::InvalidToken))).with_restricted(Fixed(secondary), ["/pkg.Svc/Allowed"]);
		let request = http::Request::builder().uri(path).header(http::header::AUTHORIZATION, "Bearer t").body(()).unwrap();
		layer.layer(Inner).call(request).await.unwrap()
	}

	fn grpc_status(response: &http::Response<Body>) -> Option<&str> {
		response.headers().get("grpc-status").and_then(|v| v.to_str().ok())
	}

	#[tokio::test]
	async fn the_restricted_authenticator_admits_only_its_paths_and_marks_the_caller() {
		let admitted = call(claims, "/pkg.Svc/Allowed").await;
		assert_eq!(admitted.headers()["x-restricted"], "true");

		let elsewhere = call(claims, "/pkg.Svc/Other").await;
		assert_eq!(grpc_status(&elsewhere), Some("16"), "UNAUTHENTICATED off the allowlist");
	}

	#[tokio::test]
	async fn an_outage_in_the_restricted_authenticator_stays_unavailable() {
		let outage = call(|| Err(AuthError::Unavailable), "/pkg.Svc/Allowed").await;
		assert_eq!(grpc_status(&outage), Some("14"), "an outage is retryable, not a verdict on the token");

		let refused = call(|| Err(AuthError::InvalidToken), "/pkg.Svc/Allowed").await;
		assert_eq!(grpc_status(&refused), Some("16"));
	}
}
