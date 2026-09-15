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

They are coupled by **two seams, both initiated by `banking`** — `concierge` still
never calls `banking`:

1. The **cross-plane bridge**: `concierge` emits user-lifecycle events
   (`events.proto` — `UserLifecycleEvent`) to its `user_outbox`, and `banking`
   **pulls** them over `UserEvents.PullUserLifecycle` (`bridge` module) to
   gate/freeze money ops.
2. The **mail relay**: `banking` **pushes** typed governance mail over
   `MailRelayService.SendGovernanceMail` (`governance` module), because this plane
   owns the only mailer and standing up a second one would duplicate the queue,
   the backoff and the daily budget. The payload is TYPED, never rendered markup;
   the recipient's address is resolved HERE from the identity record, never from
   the request; and every emailed link is pinned to `PUBLIC_ORIGIN` — a
   compromised money plane must not become a phishing cannon aimed at owners.
   WHO may receive one is decided per KIND, and the default is the strict one:
   the consilium kinds — the three payout kinds and `PAYMENT_APPROVAL`, the
   owners' question about a payment of fund-owned money — are addressed to the
   consilium, so they go to a seated owner and to nobody else. `PAYMENT_CONSENT`
   cannot use that rule — consenting to a transfer of your own money has nothing
   to do with holding a seat — so it gets its own, narrower in the dimension that
   matters: the recipient must BE the payment's subject, named in the typed
   payload and matched against the resolved identity record. The surface widens
   by exactly one person per message rather than to everyone. Every kind, under
   either rule, is refused unless the resolved address is VERIFIED
   (`users.email_verified`): each of these mails carries a link and the code that
   arms it, and an address nobody has proved belongs to the person hands that
   decision to whoever holds the mailbox (#64 closed the payout kinds' exemption).
   A consent also leaves an in-app trace in the subject's inbox
   — written regardless of what they follow, because nobody subscribes to being
   asked about their own money and no topic is followed by default — so the
   request is findable in the cabinet when the mail is late or lost; the link and
   the code stay in the mail. The fee policy pair follows the same split:
   `FEE_POLICY_APPROVAL` is a consilium kind (a seated owner, verified address,
   link + code), `FEE_POLICY_NOTICE` is addressed by identity to the one investor
   whose fund is repriced, traced in their inbox, and carries no code — its only
   link is a cabinet-relative path the dispatcher hangs off `CABINET_URL`, so the
   money plane names no host at all. Fee terms cross the wire as basis points and
   closed vocabularies; the percentages are rendered here.

Both seams are authenticated by the SAME shared bridge service token
(`BRIDGE_SERVICE_TOKEN`), compared in constant time and mounted OUTSIDE the user
auth layer. One trust relationship between the planes means one secret to rotate;
graduate to mTLS/SPIFFE at platform scale.

**Ownership** (`Role::Owner`) is governed, not administered: it is granted only by
an executed admission consilium and taken only by an executed removal, so
`UserDirectory.SetRole` refuses both directions (`governance` module; the policy is
`banking`'s `docs/CONSILIUM.md`).

**So is `Role::Admin`, and so is a permanent suspension** — see the Hard rule below.
`SetRole` refuses to GRANT `admin` (never to take it away), and `DisableUser` is
retired in favour of `HoldUser` plus `GovernanceService.OpenUserSuspension`.

---

## Where things are documented

| Topic | Source |
| ----- | ------ |
| Bring-up · `nix run` apps (`concierge` — applies DB migrations on boot, `db`) · migrations applied on boot, authored with sqlx-cli · dev shell | [`flake.nix`](./flake.nix) |
| Workspace, crate graph | [`Cargo.toml`](./Cargo.toml) |
| `runner` — the modular monolith: ONE binary (composition root) mounting the internal modules **auth**, **directory**, **bridge** (cross-plane producer), **governance** (the consilia: owner admission/removal, the user proposals over suspension/reinstatement/`admin`, + the money plane's mail relay), **platform** (platform/cabinet config: maintenance mode · announcement banner · feature flags), **notification**, **log**. `directory` + `bridge` + `governance` + `platform` + `notification` are live; `log` is a DEFERRED stub | [`runner/`](./runner) |
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
- **KYC has exactly one writer**: the `User` aggregate's `set_kyc_level` and the
  `user_outbox` drain beside it in one transaction (→ `KYC_CHANGED` → outbox →
  banking's mirror). Two ENTRY POINTS reach it, and they differ only in what they
  are allowed to decide. `users.set_kyc_level` is unconditional in DIRECTION and belongs
  to the human path (`Permission::KycManage`), because a human is precisely who may move
  a level DOWN. It is NOT unconditional in RANGE: the aggregate refuses anything above
  `domain::users::MAX_KYC_LEVEL` (3), and the `users_kyc_level_range` CHECK refuses it
  again at the column — the range belongs to the record, not to the one handler that
  happened to check it. `user_outbox.kyc_level` carries the same CHECK, `NOT VALID` on
  purpose: it is the copy banking mirrors, so future appends are bounded while the log
  keeps reporting what it reported. `users.raise_kyc_level_to` is the vendor path: it is MONOTONIC, and the
  "is this actually a raise?" comparison is taken inside the write transaction from
  the target row held `FOR UPDATE`. That must not become a read on one connection and
  a write on another — an operator committing in the gap would have their decision
  silently overwritten by a vendor's stale conclusion, which is the one thing this
  surface promises cannot happen. The verification vendor sits behind the
  `KycProvider` port and its webhook (`web/kyc.rs`, `POST /kyc/callback/didit` —
  public, HMAC over the raw body, 300s replay window) lands in that same aggregate
  call, so banking never learns a vendor exists. A provider may only RAISE a level and
  never past `PROVIDER_MAX_TIER`; every tier above it and every downgrade are human
  decisions under `Permission::KycManage`. The identity a callback acts on comes from the
  stored `kyc_cases` row, NEVER from the request body; the body's echoed `vendor_data` is
  a CROSS-CHECK against that row and is decided inside the recording transaction, because
  a refusal reached after the commit is not a refusal — it used to answer 400 over a row
  it had already moved (#54). Absent `DIDIT_*` config, both routes answer 503 — there is
  no arm that skips the signature.
- **The vendor ceiling is what the vendor actually CHECKS, and it is 1.** There is one
  Didit workflow (`DIDIT_WORKFLOW_ID`) and it verifies a document and a selfie — tier-1
  evidence. Tier 2 means "plus proof of address and source of funds" (`banking`'s
  `users.proto`), and no workflow we run asks for either, so an approval is evidence for
  tier 1 and nothing more. `/kyc/start` used to take the tier from the REQUEST BODY, and
  `start_session` then dropped it — so `{"tier":2}` bought level 2 for a tier-1 check,
  chosen by the applicant. The body no longer carries a tier at all and cases open at
  `ENTRY_TIER`. `PROVIDER_MAX_TIER` is the second half of that fix and not a duplicate of
  it: rows asking for 2 are already in the table, and clamping where the VERDICT is
  applied is the only thing that reaches a case opened before the entry point changed.
  Raising the ceiling is not a constant edit — it is a second workflow id selected by tier
  inside `start_session`, and the constant must not move ahead of it. The
  `kyc_cases_requested_tier` CHECK still reads `BETWEEN 1 AND 2` and is NOT a stale second
  copy of this constant: it bounds the tier a provider may be ASKED for, which follows the
  platform's tier model (3 and every downgrade are human), while `PROVIDER_MAX_TIER` bounds
  what an approval may GRANT and follows the configured workflow. Rows outlive that
  configuration, so the ceiling cannot live in a column constraint —
  `0014_kyc_requested_tier_intent.sql` carries the argument, including why the
  `requested_tier = 2` rows are left standing and why `NOT VALID`, which is 0013's shape
  for `user_outbox`, would break this table instead of bounding it.
- **Nothing reaches the vendor before the per-user gate.** Opening a Didit session is
  BILLED against a balance every user shares, and past that balance `/kyc/start` degrades
  fail-closed: 503 for everyone, arriving as silence, because a polite "try later" is not
  something anyone reports. So `/kyc/start` reads `KycCaseRepository::start_gate` FIRST. A
  caller with a still-running case is handed that case back — `kyc_cases.redirect_url` is
  stored for exactly this and a second session would only buy them a duplicate row that
  later reads as an abandoned attempt — and a caller past `START_MAX_PER_WINDOW` in
  `START_WINDOW_SECS` is refused 429. Both answers happen without a vendor call; that
  ordering is the entire point, not an optimisation. The gate is a read and not a lock,
  so the handler single-flights starts PER USER, in process (`web::single_flight`, the
  same helper the session refresh uses), from the gate read to the row write: a second
  simultaneous start waits for the first and is then handed its case, exactly as a
  sequential second call is (#56). In process and not a row lock, because what it spans
  is the vendor round trip. It does not reach across replicas; there the window cap is
  what bounds the race.
- **A verdict is not handled until the level moved.** Recording the decision and
  writing the level are two transactions, so `kyc_cases` saying `approved` beside an
  account still at tier 0 is a reachable state. The webhook answers 5xx when the level
  write fails and re-applies on REDELIVERY rather than short-circuiting it — the
  vendor's retry is the only thing that ever revisits a decided case, and answering
  200 to it makes that split state permanent. Re-applying is free: the monotonic
  writer compares under the row lock and emits nothing when the level is already held.
- **Verdicts are ordered by the SIGNED timestamp, never by arrival.** Didit retries at
  ~1 min and ~4 min, so a superseded `in_review` landing after the `approved` that
  replaced it is routine. `kyc_cases.event_at` holds the signed instant of the stored
  verdict; a delivery strictly older than it, or one that would move a decided case
  back to a running state, is answered 200-and-ignored. The body's `timestamp` is
  REQUIRED for this reason and its absence is a rejection: `X-Timestamp` is not
  covered by either signature, so ordering taken from the header could be rewritten by
  anyone holding one captured delivery.
- **Either webhook signature authenticates a delivery**: `X-Signature-V2` (over the
  canonicalised body) is tried first, `X-Signature` (over the raw bytes) second. The
  delivery crosses a Cloudflare tunnel, Traefik and a Next.js rewrite before reaching us,
  and any hop re-packing the JSON would break the raw form for EVERY delivery at once —
  silently, since from a user's seat it just looks like verification stopped working.
  Accepting both makes the two failure modes cancel out. The webhook's 404 on an unknown
  session is a RECOVERY path, not a loss: Didit retries 404 and 5xx twice (~1 min, ~4
  min), which is what resolves the webhook-overtakes-the-insert race. Do not "fix" it to
  200. The handler must answer inside 5s, so nothing on that path may wait on a network
  hop.
- **One document, one account -- detected, never refused.** Nothing linked two accounts
  verified by the same physical person, and by construction nothing could (#51): the
  `kyc_cases.payload` allowlist stores document type, issuing country and check outcomes,
  and identifying fields reach the database in no form at all. The scenario needs no
  forgery -- one person registers N accounts through Google OAuth and honestly verifies
  each with their own real passport, so liveness and face-match pass and every account
  reaches level >= 1. `kyc_cases.identity_digest` is the one cross-account handle this
  plane holds: `HMAC-SHA256(KYC_IDENTITY_PEPPER, issuing_state || ':' || document_number)`,
  computed in `didit::identity_digest_of` beside `metadata_of` -- the one scope a document
  number is ever visible in -- and dropped with the payload at the end of it. HMAC and not
  a bare hash because a document number is low-entropy and enumerable; the issuing state
  is part of the message because "AB123456" is not the same person in two countries. The
  discipline 0010 states is unchanged, and the test asserting `document_number` never
  appears in `payload` still holds -- this is a COLUMN precisely so it does not become one
  more key in a blob whose rule is "copy nothing unless named". `record_decision` asks,
  inside the transaction holding the case and BEFORE the status that would grant a level
  is written, whether that digest has already bought a DIFFERENT user a level. Two facts
  OR-ed, and both are load-bearing: a recorded `approved` case, because the level itself is
  written by a LATER transaction (`apply` -> `raise_kyc_level_to`) and a level-only question
  would miss the twin for exactly as long as that gap lasts -- a gap that is permanent
  whenever `apply` fails between the two writes; and `kyc_level >= 1`, because `approved` ->
  `kyc_expired` and `approved` -> `declined` are routine vendor events that leave the level
  standing. The lookup is serialised per digest with `pg_advisory_xact_lock`: the case row
  lock covers one case, and two verdicts on the same document would otherwise not see each
  other. A unique index would be the shorter answer and is not available -- the same person
  re-verifying their own account legitimately produces a second approved row with the same
  digest, and no index predicate can tell that from a second account. On a hit the verdict
  is recorded as `held_duplicate`, no level moves, and an `error!` (-> Sentry) puts it in
  front of an operator. NOT a refusal: the honest
  explanations are real -- a lost account remade, a shared device, a family -- and an
  automatic rejection would lock those people out with no recourse and no human involved.
  The hold is a DECIDED status on purpose: this plane has no RPC that closes a case, so a
  running one would pin `/kyc/start` to the spent vendor session for ever. Decided, the
  user may start a fresh attempt, and the operator's move is `SetKycLevel` once they have
  looked. `KYC_IDENTITY_PEPPER` is OPTIONAL and never `required_in("production")`: absent
  it no digest is computed and the check is skipped, which is where this plane stood before
  the column existed, and a detection whose absence refuses to boot would take sign-in down
  for everybody to close a hole that was already open. Because nothing else can notice that
  state -- it is in no preflight -- the boot logs it once at `error!` when a vendor is
  configured and the pepper is missing or too short to be a key (under 32 characters is
  refused, not used). The secret still has to be provisioned in `rpi5.nix` (`scopes.nix`
  platform tier, the concierge env map, `secrets/platform.json`) or the detection is off in
  production. Rotating the pepper invalidates every stored digest, and cases decided before
  the pepper was set keep a NULL one for ever -- there is no backfill, because the document
  number they would be computed from was never stored.
- **Vendor status words are copied, never retyped.** The match is case-sensitive, so a
  near-miss does not fail loudly — the arm just never fires. `"Kyc Expired"` spent a
  while here as `"KYC Expired"`, silently unclassifiable. An unknown word is answered
  200-and-ignored (a growing vocabulary must not break the endpoint) with an `error!` so
  a human adds the arm.
- **A user never meets a vendor failure.** `/kyc/start` collapses "no vendor configured"
  and "vendor would not open a session" (balance, quota, outage, timeout, nonsense) into
  one 503 with one stable body — `{"error":"kyc_unavailable","contact":"<SUPPORT_EMAIL>"}`
  — so the cabinet needs one screen and the vendor's own words never reach a browser.
  Vendor codes are deliberately NOT enumerated: we do not know which one means "out of
  balance" and guessing would be brittle exactly where it costs most. The detail goes to
  `tracing::error!` (→ Sentry), because from the user's side this failure is SILENT — it
  looks like a polite "try later" that nobody reports.
- **Every comparison against a presented secret is constant time**, with an explicit
  length guard in front of `subtle::ConstantTimeEq` (which short-circuits on a length
  mismatch, so without the guard a wrong-length candidate is distinguishable from a
  wrong one of the right length). That is the bridge service token
  (`support::authenticate_service`), the Didit webhook HMAC (`infrastructure::kyc::didit`),
  the consilium self-decision code (`infrastructure::governance`), the refresh-token secret
  (`evconcierge_auth::management`) and the `x-ev-csrf` token (`web::routes::verify_csrf`).
  Whether any one of them is a practical timing oracle is not the test — a plane that
  states this discipline and then has one check quietly doing `!=` (#52) is a plane whose
  next reader takes the exception for the rule. The CSRF check is also the STRICTER of the
  two planes' and must stay so: the header is matched against the readable cookie AND the
  server-side copy in the session locker, and the whole check runs BEFORE the session is
  read, so a request that fails it never touches session state.
- **Stopping an account is TWO verbs, and the split is the emergency budget.** A freeze
  is the only control that stops money ALREADY queued — banking re-reads the frozen flag
  in `require_dispatchable` at dispatch, so a freeze catches a withdrawal inside the
  dispatcher's sweep. Moving that wholesale to a quorum by mail would trade a ~30s brake
  for one that takes hours, and a broadcast made in those hours is irreversible; so
  `DisableUser` is retired (it refuses, naming both replacements) and splits into
  `HoldUser` — one operator, `Permission::UserSuspend`, `users.suspended_by =
  'admin_hold'` with `hold_expires_at = now + HOLD_TTL_SECS` (24h) — and
  `GovernanceService.OpenUserSuspension`, the owners' proposal, which writes
  `suspended_by = 'governance'` and carries no deadline. One actor may stop money
  temporarily and never permanently — and "temporarily" is enforced, not assumed: a
  hold is refused while one is live and for `HOLD_COOLDOWN_SECS` (7 days, longer than
  a proposal lives) after one ends (`users.hold_ended_at`), unless a suspension
  proposal about the account is OPEN, in which case the owners are deciding and the
  hold extends until they have. Re-holding used to restart the clock, which let one
  admin hold an investor indefinitely with no owner asked. An account holding the
  `admin` or `owner` seat is held only by an owner (persisted role, decided under the
  target's row lock) — an admin who could hold the owners could hold them out of the
  votes that stop the hold — and nobody holds their own account. `ReinstateUser`
  reads `suspended_by` and is the mirror rule: one act for a hold, refused for a
  verdict (naming `OpenUserReinstatement`), or the consilium would be advisory. A disabled row with `suspended_by IS NULL` predates
  the column and deliberately keeps the OLD semantics — one-act, never lapsing — because
  that is the rule those accounts were suspended under; there is no backfill.
- **The hold sweep is the ONE thing in this plane that sweeps.** Consilium expiry is
  lazy on purpose (a write path expires a due proposal before acting, read paths project
  it as expired), so nothing has to be running for a stale proposal to be unusable. A
  hold cannot work that way: its whole purpose is the frozen flag the money plane
  MIRRORS, and the money plane learns of a change only from a `user_outbox` row — a
  lapse that were merely projected would release the account here and leave it frozen
  there, forever. `dispatch::run_hold_sweep` (every `HOLD_SWEEP_INTERVAL_SECS`) is
  therefore load-bearing: if it stops, one operator's 24h brake quietly becomes
  indefinite.
- **`Role::Admin` is granted by proposal and revoked by one act.** `SetRole` refuses to
  GRANT it (naming `GovernanceService.OpenAdminAdmission`) for a relative of the reason
  it refuses `owner`: an operator who can appoint operators can appoint accomplices, and
  the seat carries every identity mutation except role granting. Taking it away stays a
  single act deliberately — containing a rogue operator must never be the slower path.
  The refusal is decided INSIDE the write transaction from the row held `FOR UPDATE`,
  the same TOCTOU argument as the `owner` refusal beside it.
- **The USER consilia pass on a MAJORITY, the OWNER consilia on unanimity**, and the
  asymmetry is argued in `domain::governance::majority`. Unanimity guards the owner
  roster because a minority able to add owners by majority grows itself into a majority;
  neither an `admin` seat (which cannot vote and cannot be granted `owner`) nor a
  suspension (defensive, reversible by the same body) can amplify itself that way.
  Against that, unanimity here would COST safety: ratifying a hold races a 24h clock, and
  under unanimity one unreachable owner does not delay the verdict — they decide it, by
  releasing a compromised account at the deadline. What is preserved is the property that
  matters: the initiator is excluded from the voter set and the threshold is at least
  one, so no single actor ever acts alone. All three kinds share ONE aggregate
  (`UserProposal`), one table and one `Lifecycle`, for the reason `0009_governance.sql`
  already gives for its two: near-identical copies drift the first time one is edited.
- **Two audit logs, answering two questions.** `governance_event` is "what happened to
  this PROPOSAL" — keyed by the three proposal ids under a CHECK that exactly one is set,
  and the reason it is one log is that "who has held a seat, and by whose decision" is a
  single ordering. `admin_action` is "what has been done TO this person, by whom" —
  keyed by the subject, and the home of the rows suspension, reinstatement, `SetRole`,
  `SetKycLevel` and `RevokeTokens` never wrote at all. Every one of them is appended in
  the SAME transaction as the change it describes: a log that can be missing the entry
  for a change that happened is a source of false confidence, so a rolled-back command
  takes its audit row with it. `actor_user_id` is NULL only where nobody acted (the hold
  sweep) — never as a stand-in for an actor we failed to resolve.
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
