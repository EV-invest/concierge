# Agent Instructions

> **Self-update rule:** If anything here becomes stale — stack, layout, tooling, conventions — update this file as part of the same change.

> **No duplication:** This file holds only cross-cutting rules. Bring-up and the `nix run` apps are documented in `flake.nix`; per-area patterns move into per-crate READMEs/`PATTERNS.md` as the project grows — link to them, don't restate them here.

Org-wide conventions & context: [`.github`](../.github) — for large tasks requiring org-level context (architecture, team conventions, resources), read that repo first.

---

## The two planes

`concierge` is the **USER/IDENTITY + PLATFORM** plane of the EV Investment
platform: user-session auth, the user directory/profile, notifications, and
logs. Its sibling `banking` is the **MONEY** plane (TigerBeetle ledger,
money-operation authorization). The two run **independent auth flows** and share
no database.

The only coupling is a one-way **cross-plane bridge**: `concierge` emits
user-lifecycle events (`events.proto` — `UserLifecycleEvent`) to its
`user_outbox`, and `banking` **pulls** them over the `UserEvents.PullUserLifecycle`
RPC (`bridge` module) to gate/freeze money ops. `concierge` never calls `banking`.
The seam is authenticated by a shared bridge service token (`BRIDGE_SERVICE_TOKEN`),
mounted OUTSIDE the user auth layer; graduate to mTLS/SPIFFE at platform scale.

---

## Where things are documented

| Topic | Source |
| ----- | ------ |
| Bring-up · `nix run` apps (`concierge` — applies DB migrations on boot, `db`) · migrations applied on boot, authored with sqlx-cli · dev shell | [`flake.nix`](./flake.nix) |
| Workspace, crate graph | [`Cargo.toml`](./Cargo.toml) |
| `runner` — the modular monolith: ONE binary (composition root) mounting the internal modules **auth**, **directory**, **bridge** (cross-plane producer), **platform** (platform/cabinet config: maintenance mode · announcement banner · feature flags), **notification**, **log**. `directory` + `bridge` + `platform` are live; `notification` + `log` are DEFERRED stubs | [`runner/`](./runner) |
| `evconcierge_auth` — the real `AuthService` issuance surface (Ed25519 signer · JWKS · Google OAuth code+PKCE · Redis-backed refresh rotation with reuse detection · `Exchange`/`Refresh`/`Logout`/`ListSessions`/`RevokeSession`/`Jwks`) provisioning users to the directory over an in-process `Provisioner` channel, **plus** the stateless token-verification flow imported by downstream service repos by git. No-op-until-configured: with no signing key it runs inert | [`auth/`](./auth) |
| gRPC contracts — `proto/concierge/v1/` (source of truth) → Rust stubs via `tonic-build`. `evconcierge_auth` depends on `contracts`; not vice-versa | [`contracts/`](./contracts) |
| Shared identity types · DDD building blocks (`ev::architecture`) | [`domain/src/`](./domain/src) |
| **Design** — operator (admin) surface over this plane | [§ Design](#design) |

---

## Design

The operator-facing design surface over this plane is **admin** — the operator
console over the hub + microservices, covering the identity/platform slice:
users (KYC · roles · `token_version` revoke), sessions & devices, feature flags.
Its frontend lives in the `banking` clients repo, not here; the design is part of
the shared EV Figma file (`e0V2P1cQpEFRuXTeNtEMh6`) — a dark-navy **Inter** system
with every value bound to `ev/*` variables, shipped to clients as the published
`@evinvest/uikit`.

| Surface | What | Figma |
| ------- | ---- | ----- |
| **admin** | Operator console — users · KYC · roles · `token_version` revoke · sessions · feature flags (the identity/platform slice) | [node 346-27](https://www.figma.com/design/e0V2P1cQpEFRuXTeNtEMh6/Main?node-id=346-27) |

**Observability** (surfaced in admin): **Sentry** (errors + tracing across the
plane) · **PostHog** (product analytics, feature flags). Wired only through the
`ev` crate features (`error_monitoring`, `analytics`) — a no-op until `SENTRY_DSN`
/ `POSTHOG_KEY` are set, so unconfigured local/CI runs are unaffected.

---

## Principles

- Simple > complex. Delete before adding.
- No friction for users (no popups, forced clicks).
- Every change must impact user trust, safety, or platform reach.
- GitHub is source of truth.

---

## Commits

```
type(scope): description   # ≤72 chars, imperative, no period
```

Types: `feat` `fix` `perf` `refactor` `revert` `docs` `style` `test` `build` `ci` `chore`

- No AI co-author trailers: never append `Co-Authored-By: Claude …` (or any
  AI/agent co-author) to commit messages or PR bodies.
- Commit when you're confident in the change — don't leave work uncommitted.
  Split it into small, focused commits (one logical change each); never land a
  single commit of thousands of lines.

---

## Hard rules

- The **auth** and **directory** modules are the real identity plane (Postgres
  control plane, migrations on boot): auth issues/verifies tokens, the directory is
  a Postgres-backed user repository (provision/profile/admin) that emits cross-plane
  lifecycle events to `user_outbox` in the write tx. The **bridge** module serves
  those rows to banking over `UserEvents.PullUserLifecycle` (read-only; shared bridge
  token; mounted outside the user auth layer). The **platform** module is the
  operator console's platform/cabinet config surface (maintenance mode, announcement
  banner, feature flags) behind the shared RBAC gate (`authz`). `notification` and
  `log` stay DEFERRED stubs (`tonic::Status::unimplemented`); their application
  layers are placeholders to grow into. Health returns `"ok"`.
- Keep `cargo check` independent of a live database at BUILD time: use runtime
  queries (`sqlx::query*`), never the compile-time `sqlx::query!` macros. Tests
  hit a REAL Postgres (no DB mocks); the binary applies migrations on boot.
- No extra deps, abstraction layers, or unasked-for features.
- No comments explaining _what_; only _why_ if non-obvious.
- No `.env*`, secrets, or large binaries committed.
- Run `cargo clippy` before pushing; the `treefmt` pre-commit hook formats Rust,
  Nix, and proto.
- `domain` is the shared source of truth for identity types; the `runner`, the
  downstream service repos, and other repos depend on it, never on each other.
  The I/O-free DDD tactical building blocks (generic traits) live in the
  `architecture` feature of the external `ev` crate
  ([`EV-invest/lib`](https://github.com/EV-invest/lib)); `domain` depends on it,
  re-exports it as `domain::architecture`, and stays wasm-safe — so the
  wasm-unsafe `evconcierge_auth` must never be a dependency of `domain`.
- `evconcierge_contracts` (vendoring `proto/`) is the single dependency other
  service repos import by git — it gives them the gRPC stubs and, via
  `evconcierge_auth`, the standard token-verification flow.
- This is the **identity/platform** plane — no TigerBeetle, no money ledger, no
  money-operation authorization. Those belong to the `banking` repo.
- Cross-cutting **observability** goes through the shared libraries, never a
  vendor SDK wired by hand: on the Rust side the `ev` crate features
  (`error_monitoring`, `analytics`). Each is a no-op until its env is set
  (`SENTRY_DSN`, `POSTHOG_KEY`), so unconfigured local/CI runs are unaffected.

---

## PR / Issue flow

- Branch: `<user>/<short-slug>`
- One PR per logical change; link the closing issue.
- All discussion on GitHub, not Discord.
