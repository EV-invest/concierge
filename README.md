# concierge

`concierge` is the **user / identity + platform** plane of the EV Investment
platform. It owns user-session auth, the user directory/profile, notifications,
and logs. Its sibling repo `banking` is the **money** plane (TigerBeetle ledger,
money-operation authorization); the two run independent auth flows and share no
database. The only coupling is a one-way bridge: `concierge` emits
user-lifecycle events to its `user_outbox`, and `banking` **pulls** them over the
`UserEvents.PullUserLifecycle` RPC to gate/freeze money ops. `concierge` never
calls `banking`. The seam is authenticated by a shared bridge service token
(`BRIDGE_SERVICE_TOKEN`); graduate to mTLS/SPIFFE at platform scale.

`concierge` is a **modular monolith** — one runner binary whose internal modules
are `auth`, `directory`, `notification`, and `log`. Downstream service repos
import `evconcierge_contracts` (gRPC stubs) and `evconcierge_auth` (stateless
token verification) by git, exactly as the `banking` plane exposes its own
contracts/auth crates.

## Layout

| Path | What | Stack |
| ---- | ---- | ----- |
| [`runner/`](runner) | the modular-monolith binary — composition root mounting modules `auth` · `directory` · `notification` · `log`; opens the Postgres control plane and applies `runner/migrations` on boot | Rust · tonic · sqlx |
| [`auth/`](auth) | `evconcierge_auth` — the `AuthService` issuance surface (Ed25519 signer · JWKS · Google OAuth code+PKCE · Redis-backed refresh rotation) + the stateless token-verification flow (imported by downstream repos) | Rust · tonic · JWKS |
| [`contracts/`](contracts) | `evconcierge_contracts` — gRPC wire contracts (`proto/concierge/v1/` → tonic stubs) | Rust · tonic-build · proto3 |
| [`domain/`](domain) | shared identity types (pure, wasm-safe) over `ev::architecture` | Rust |

`directory` is the live module; `notification` and `log` are deferred stubs.

## Run

Every app is a flake app. `nix run` resolves the repo root at runtime, so
there's no need to enter the dev shell first.

The dev topology (ports, database URLs) lives in the flake's `ports` attrset —
a single shared Postgres cluster and Redis serve every ev_invest repo, so there
are no hardcoded ports here.

| Command | Brings up |
| ------- | --------- |
| `nix run .#db` | ensure the shared ev_invest Postgres is up (+ this repo's `concierge` database) |
| `nix run .#redis` | ensure the shared ev_invest Redis is up |
| `nix run .#concierge` | the runner binary (all gRPC modules in-process; applies DB migrations on boot; ensures the shared Postgres + Redis first) |

Equivalently, from the dev shell: `cargo run -p concierge`.

A dev shell with the full toolchain (Rust nightly + `wasm32`, protobuf,
treefmt, pre-commit) is auto-activated by `.envrc` + direnv, or via
`nix develop`.

## License

Licensed under [Blue Oak 1.0.0](LICENSE).
