# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2026-08-18

### Added

- **At-rest encryption posture is now visible.** A new **Inventory → Data
  Protection** lens shows whether your cloud storage and databases are
  encrypted, with what, and — crucially — *whose key*. S3 buckets and RDS
  instances already reached Inventory after a cloud discovery, but their
  encryption posture stayed in raw discovery metadata where nothing rendered
  it, and they were listed as TLS endpoints, which they are not.
  Encryption is presented as a custody ladder rather than a tick: a bucket
  using an AWS-managed key and one using your own KMS key both read
  "Encrypted", but at different severities, so the difference between a key
  you hold and a key your provider holds cannot hide behind two identical
  green ticks. Where the provider reports SSE-KMS without saying whose key it
  is, the lens says "Key owner unknown" rather than assuming the better case.
- **"Could not determine" is a first-class result.** If a credential cannot
  read a bucket's encryption setting, that is reported as *not assessed* —
  visually distinct from both encrypted and unencrypted, and never scored as
  a pass or a failure. A missing IAM grant should not read as a clean bill of
  health.
- `GET /api/v1/inventory-service/crypto-applications` returns at-rest
  encryption records, filterable by resource type, assessment state and risk.

### Changed

- At-rest resources no longer report a fabricated `TLS`/`443` endpoint. They
  now carry `AT-REST` and no port. **Upgrade note:** the port is part of the
  identity used to match a rediscovered asset, so buckets and databases
  discovered under 0.9.0 will not match after upgrading and will be recreated
  alongside the originals. Only installs that ran S3 or RDS discovery on
  0.9.0 are affected; remove the superseded rows once rediscovery has run.

### Fixed

- Requesting a compliance re-evaluation while the reconcile worker is
  disabled no longer consumes the hourly cooldown and reports acceptance for
  work that could never run. It now reports the service as unavailable and
  leaves the cooldown intact.

## [0.9.0] - 2026-08-18

### Added

- **AWS integrations can authenticate by assuming a role, not just by access
  key.** Discovery → Cloud now offers an **Authentication** choice on an AWS
  integration: an access key (long-lived, or temporary with a session token) or
  **`sts:AssumeRole`** against a role in your own account, with an optional
  **external ID** and role session name (default `vistaplatform-discovery`).
  Static keys are optional in assume-role mode — supply them and the AssumeRole
  call is signed with them, leave them blank and the platform's own ambient AWS
  identity is used. Session tokens now actually work in access-key mode; they
  were accepted by the form and silently dropped before reaching AWS.

  **Test connection** now builds its credentials through the same code path
  discovery uses, so a green test proves discovery will authenticate the same
  way — previously it assembled its own static-key config and could pass while
  discovery failed, and for an assume-role integration it tested credentials
  discovery would never use. Cross-account setup, the trust policy, and why the
  external ID exists are documented in
  `docsv4/core/features/aws-cloud-discovery.md`.

- **KMS, S3 and RDS are selectable in the AWS discovery dialog.** All three were
  implemented in the backend but absent from Discovery → Cloud, so no user could
  start a run for them. The dialog now offers all eight AWS resource types and
  marks the two that are enumerated account-wide — CloudFront and S3 — as
  `GLOBAL`, disabling the region picker (and omitting `regions` from the
  request) when the selection contains only those.

### Fixed

- **API Gateway and CloudFront were interrogated for real.** Both returned a
  hard-coded "HTTPS on port 443" stub with no TLS detail at all. API Gateway now
  reads the custom domains mapped to the API and reports each domain's minimum
  security policy, endpoint type, status and bound ACM certificate. CloudFront
  now reports the viewer-side minimum protocol version, SSL support method and
  certificate, **plus one record per custom origin** — a distribution can serve
  viewers over TLS 1.2+ while reaching its origin over TLS 1.0 or cleartext, and
  no client-side handshake against the CloudFront domain can reveal that.
  Requires the new `cloudfront:GetDistributionConfig` grant.

- **ELB SSL-policy TLS versions were fabricated.** Any policy with any cipher
  was reported as permitting TLS 1.2 and TLS 1.3, regardless of what it actually
  permits — so `ELBSecurityPolicy-TLS-1-0-2015-04`, which still accepts TLS 1.0,
  was reported as modern-only. Reporting a weak protocol as strong is the worst
  failure this pipeline can have. Protocol versions now come from the policy's
  own `SslProtocols`.

- **The reported TLS version is now the minimum the endpoint permits.** It was
  whichever version happened to come first out of a Go map iteration, and was
  then overwritten by whatever our own client negotiated during the handshake
  verification — which hides exactly the finding this feature exists to produce.
  The permitted set is recorded alongside it, and the negotiated version is kept
  separately rather than overwriting the permitted minimum.

- **An unreadable S3 bucket is no longer reported as encrypted.** Any failure to
  read the bucket encryption configuration — `AccessDenied`, a throttle, a
  network blip — was treated as "no configuration, so AWS default SSE-S3
  applies" and recorded as a measured encrypted bucket. Only S3's specific
  "no bucket-level configuration" response licenses that conclusion now;
  everything else is recorded as **could not determine**. Bucket regions are
  also resolved per bucket instead of being stamped with the integration's
  default region (requires the new `s3:GetBucketLocation` grant, one extra call
  per bucket per run).

- **The AWS region list covers the commercial partition.** It was 15 regions;
  regions added since are now selectable. GovCloud and China remain unsupported
  — separate partitions, credentials and endpoints.

- **Documentation corrected.** `docsv4/core/features/aws-cloud-discovery.md`
  claimed regions were scanned in parallel (they are sequential), that AWS rate
  limits were "respected with exponential backoff" (there is no platform-side
  retry configuration — only the AWS SDK's standard retryer defaults), and that
  credentials were "cleared from memory after use" (they are not; the claim is
  removed rather than replaced). The documented minimum IAM policy was also
  insufficient: it omitted `sts:GetCallerIdentity`, which the Test Connection
  button calls, and `acm:DescribeCertificate`, which certificate enrichment
  calls, and named a non-existent `apigatewayv2:` IAM namespace instead of
  `apigateway:GET`. The doc now also states plainly that KMS results have no
  key-inventory view in the tenant UI, that KMS/S3/RDS failures leave a job
  reporting success with zero results, and that nothing here has been verified
  against a live AWS account.

## [0.8.0] - 2026-08-17

### Added

- **Re-evaluate your compliance posture on demand.** Risk & Compliance → Posture
  gains a "Re-evaluate now" control. Stored compliance scores are recomputed when
  an asset or certificate changes, when a framework is activated or published, or
  when someone asks — and until 0.8.0, "someone" could only be the platform
  operator. After a remediation you can now force convergence yourself rather
  than waiting for the next change to trigger it.

  Rate-limited to **once per hour per organization**, regardless of who clicks:
  a re-evaluation walks every activated framework across your whole inventory,
  so the cost is real. The button shows when the last run happened and when the
  next is available, and is disabled until then rather than failing when pressed.
  Requires the `compliance.manage` permission ( gate model;).

### Security

- **Selecting a subscription tier now requires permission and an entitlement.**
  The tier-selection endpoint had no permission check and no billing check, so
  any signed-in member — including a read-only viewer — could move the
  organization onto a higher tier without paying. It now requires
  `billing.update`, and a paid tier is refused unless the organization actually
  holds a subscription for it.

  A second route to the same outcome is closed with it: the signup path accepted
  any tier flagged as a trial without checking its price, so a **paid** tier
  flagged as a trial was selectable during registration. Signup itself is
  unchanged for legitimate use — a brand-new organization with no subscription
  still completes onboarding onto the free tier.

- **Role assignment cannot exceed the assigner's own permissions.** The RBAC
  role-assignment API enforced that ceiling, but the older paths that assign a
  role *by name* — creating a user, updating a user, and inviting one — did not,
  so an administrator could mint a user or an invitation carrying permissions
  they do not themselves hold. All of them now enforce the same bound, and a
  pending invitation is re-checked **at the moment it is accepted**, so an
  invitation issued before this release (or by someone who has since lost the
  permission) cannot materialize an elevated role.

  Note for administrators: an invitation whose issuer is unknown — very old
  rows, or an inviter whose account was deleted — is now refused at acceptance
  if it carries a role with permissions. Re-issue it.

- **Platform alerts no longer fail to deliver when the message broker is down.**
  Alert notifications carry a reserved platform identifier that the primary
  delivery path knows to treat as platform-scoped; the HTTP fallback added in
  0.7.0 did not, so on that path a platform alert was handled as though it
  belonged to a tenant, matched no delivery rules, and was rejected by the
  database.

- **Algorithm-catalogue writes moved off the public host.** Creating or updating
  an entry in the algorithm reference is a platform-operator action, but it lived
  on a path the tenant UI also reads, so it could not be separated by host and
  remained reachable on the public address — gated by permission, but present.
  Those two operations moved to a dedicated administrative path that the existing
  host split covers; reading the catalogue is unchanged.

### Fixed

- **`make build-services` failed on the first command.** The build targets
  compiled a single `main.go` rather than its package, which excludes every
  sibling file, so building from source stopped with `undefined: edition`. The
  sensor and Windows agent build scripts had the same defect — the path our own
  guidance points to for anyone who prefers building the binaries themselves. The
  target also claimed to build all backend services while building 11 of 16;
  it now builds all 15 that do not require libpcap, and an automated check keeps
  it complete.

- **Removed a stale internal endpoint that returned placeholder compliance
  results.** An unused, unreachable handler returned hardcoded PCI-DSS and
  NIST-800-53 control outcomes that were never derived from any inventory.
  Nothing called it and nothing displayed it, but it had no business in a
  codebase you are invited to read.

### Changed

- **Nightly builds and security scanning.** Secret-detection, dependency and
  static-analysis findings now publish to the repository's security dashboard
  with history, instead of only into a build artifact. Two intermittent test
  failures that made the nightly build unreliable are fixed — one a database
  lock ordering problem between concurrent test packages, the other a
  credential-leak check whose search strings were short enough to match
  encrypted output by chance and raise a false alarm.

- **Documentation now describes Core accurately.** Several pages walked through
  capabilities that are not in a Core build — identity-provider federation, CMDB
  synchronization, SIEM forwarding, white-labelling and billing — and the feature
  summary listed active OT/ICS probing as included. Passive OT/ICS observation
  (Modbus, DNP3, BACnet-SC) **is** Core; *active* OT probing and the OT inventory
  lens are Enterprise. The contributor guide's verification commands also
  referenced targets that are not part of this repository.

## [0.7.0] - 2026-08-15

### Added

- **Two alert types that were listed as active can now actually reach you.**
  Failed-login bursts and breached metric thresholds were both declared live in
  the alert catalogue, and neither could form an alert. Their detectors live
  outside compliance-engine, and the generic `alerts.raise` rail they needed had
  never had a single producer — so both published a bare notification instead,
  with no deduplication, no escalation, no auto-resolve, and no entry on
  Remediation → Alerts. A brute-force burst and a breached threshold, arguably
  the two most urgent operational signals, were invisible on the page built to
  show urgent things. Both now open, escalate and resolve like every other alert
  type.

  Two further faults sat underneath, either of which alone kept them silent.
  The failed-login rule matched the event name `user.login.failed` while the
  login handler emits `user.login_failed` — a dot against an underscore, which
  means **this detector had never once fired**. And it declared a threshold of
  five failures in five minutes that nothing read, so repairing only the name
  would have paged you on a *single* failed login. The metric evaluator asked
  for a one-hour window of readings that are stamped an hour in the past, so the
  set it evaluated was always empty.

- **Platform operators are told when the platform breaks.** A fresh install had
  no platform notification channels or routing rules at all, so `service_down` —
  a critical alert whose detector works correctly — reached zero recipients
  until an operator configured delivery by hand. Installs now seed an operator
  bell and an admin email channel that **stores no address**: it names the
  platform-admin role and resolves live members at send time, so it works before
  anyone has entered an address and tracks admin membership as it changes.

  Separately, every platform alert was being routed as though it belonged to a
  tenant. The reserved platform sentinel id was passed through as a real tenant,
  so platform notifications matched no rules and failed a foreign key — the
  seeded defaults could never have been consulted on the live path. Default
  monitoring thresholds are seeded too, so threshold alerting has something to
  evaluate out of the box.

  Both seeds are **first-install-only by design**: they apply when no platform
  delivery is configured at all, and never touch a configured one. An
  administrator who edits, disables, renames or deletes any of it keeps exactly
  what they have, on every subsequent upgrade.

- **Failed notification deliveries are retried.** The delivery queue had
  retry-count and next-attempt columns and was only ever deleted from, never
  written — a send that failed was attempted once and lost. Failures now retry
  with exponential backoff, bounded at five attempts, and a delivery that
  exhausts them leaves a durable record naming the attempt count rather than
  quietly stopping. Retries are scoped to the **specific channel that failed**,
  so a webhook outage cannot re-send an email that already arrived.

  Alert fan-out also gained the HTTP fallback its peers already had. Alerts
  notify only when they open or escalate, never on re-raise, so a message broker
  outage at that moment lost the notification permanently with no second chance.

- **Custom roles.** Settings → People & Access → Roles & Permissions is now a
  working screen rather than a list. Tenant administrators can create a role,
  set exactly which permissions it grants from the full catalogue, and delete it
  again. Until now the tenant side had no way to define a role at all: the five
  built-ins were the only options, and the two endpoints that looked like they
  supported editing were stubs — the permission matrix always returned an empty
  list and the save endpoint returned `200` without writing anything, so a UI
  built on them would have reported success and discarded every edit
 .

  The **built-in roles stay read-only**, and the screen says why: the seeded
  role definitions are reconciled on every upgrade, so an edit to one would be
  silently reverted the next time you upgraded. Custom roles are untouched by
  that reconciliation.

  Two locks appear in the permission grid. A permission you do not hold yourself
  cannot be added to a role — otherwise `users.manage` would quietly be a
  superuser permission, since its holder could mint a role carrying anything and
  assign it to themselves. Permissions a role already holds that you lack are
  shown checked-but-locked and are preserved when you save. Deleting a role that
  people still hold asks where to move them first, and a role wired into an SSO
  group mapping is refused outright rather than silently breaking federated
  sign-in.

### Changed

- **The AI-agent interface now records what it was asked for.** The MCP server
  hands tenant inventory, compliance state and CBOM artifacts to AI agents and
  kept no record of any of it — there was no way to answer "what did the agent
  read, and on whose behalf". Every tool call and every credential decision is
  now recorded: which tool, which tenant, which identity, and how much data came
  back. Tool arguments are filtered through an allowlist, so the trail never
  accumulates a field nobody vetted, and the data itself is never recorded —
  only that it was read, and how much.

- **Audit logging now covers every service.** Seven services wrote nothing to
  the audit trail, including two that modify tenant data. All sixteen now record
  to it, and an automated check fails the build if a service stops (,
 ). Along the way: a shared helper for recording audit entries had been
  returning nothing to every caller since a dependency changed how it stores
  request values — nine call sites had been silently skipping their audit entry,
  with no error anywhere.

- **Compliance findings from frameworks you never activated are no longer
  reachable.** Listing already excluded them, but fetching, modifying or reading
  the history of one by its id did not, so a direct request returned and could
  change a finding outside your activated set.

- **Permissions have a single source of truth.** The permission catalogue and
  the per-role grant rules were maintained by hand in five places across three
  languages — including, as it turned out, inside the very script that checks
  for permission drift. That script's copy had itself drifted and was reporting
  the wrong grants, and the parity test guarding the rest covered one role out
  of five. All five are now generated from `standards/permissions.yaml` by
  `make generate`, and `make audit` fails on drift. No role's permissions change
  as a result of this: the generated output reproduces the previous state
  exactly, which is asserted rather than assumed.

- **A control now passes or fails on whether anything violated it, not on how
  severe it is.** Severity was doing two jobs: it weighted the score *and* it
  decided the verdict. Because a finding's severity is copied from the control's
  own rating, that made a Low-severity control incapable of failing — it
  reported PASS while carrying open findings, and a Medium one could only ever
  report WARN. One framework emitted two active findings and simultaneously
  reported "score 100, 1 of 1 controls passing". Severity keeps the job it is
  good at — it weights the score and labels each finding — and the violation
  decides the result. **WARN is retired**: it earned no score either way, so it
  read as "not failing" while counting as a failure in the arithmetic.

  **Controls that were never checked are no longer counted as passes.** Three
  different situations — no measurement rule configured, nothing in scope to
  check, and the check itself failing — all scored as a pass, so a half-authored
  framework, an empty inventory or a broken extractor could each report 100%.
  They are now reported as **Not assessed**, with the reason available on the
  result, and excluded from the score on both sides of the fraction. A score is
  shown alongside its coverage ("8 of 11 controls assessed"), and a framework
  with nothing assessed shows **—** rather than a number. An extraction failure
  is now logged and counted rather than silently discarded.

  **Your scores will move — but not at the moment you upgrade.** Frameworks whose
  only violations were low-severity previously reported as fully passing and will
  now report those failures; frameworks scoring 100% on unevaluated controls drop
  to their assessed subset. Nothing about your inventory has changed — only what
  the platform is willing to call a pass.

  Stored scores are recomputed **on the next reconcile**, not by the upgrade
  itself: an asset or certificate change, a framework activation or publish, or
  the platform-admin re-evaluation action. Until one of those happens the stored
  rollup keeps its previous value, so an operator who upgrades and sees an
  unchanged score is looking at a stale rollup, not a failed upgrade. Pages that
  evaluate live — Posture in particular — show the new behaviour immediately,
  which means the two can disagree in the window between. To converge everything
  at once, trigger a re-evaluation per tenant.

  The model follows the separation of *result*, *severity* and *weight* that
  NIST's XCCDF (IR 7275) defines, and its "strict scoring" rule that any
  violating instance fails the control.

### Fixed

- **Alerts at the lowest severity reached nobody.** Default notification routing
  covered critical, high, medium and low, and silently omitted informational —
  which is where plan-usage warnings and billing notices land, and where any
  unrecognized severity is normalized. Those notifications were recorded as sent
  while reaching zero channels, indistinguishable from a real delivery. New
  tenants get the corrected routing, and **existing tenants are repaired on
  upgrade** — narrowly, matching only rules still carrying the shipped defaults,
  so customized routing is never overwritten.

- **Digest notification rules could not be created.** Choosing a digest in the
  routing-rule dialog sent a frequency the database rejects, so saving failed
  outright; the rules table also displayed existing digest rules as immediate.
  Three real cadences (hourly, daily, weekly) are now offered.

- **Three billing notification fallbacks were posting to a URL that does not
  exist**, so when the message broker was unavailable those notices were lost
  rather than delivered over HTTP. One was also unsigned.

- **Integration credentials are no longer returned to every signed-in user.**
  `GET /integrations` had no permission check and decrypted `auth_config` before
  returning it, so any member of the tenant — including read-only roles and
  read-only API tokens — could read the plaintext API keys and passwords for
  connected SIEM, CMDB and ITSM systems. The endpoint now requires
  `settings.read`, **and** secret values are redacted from list responses
  regardless of who asks: a browse surface never needs the secret back. If you
  have tooling that reads credentials out of this endpoint, it will now receive
  `[redacted]`.

- **Audit permissions are real permissions.** `audit-service` had been running a
  private authorization scheme: a hardcoded check against the user's role name,
  using permission names that existed nowhere in the permission catalogue and
  were never stored against any role. No tenant could grant audit access to
  anyone, because there was nothing to grant. Audit routes now use the same
  `audit.read` / `audit.manage` permissions as everything else, which also makes
  them assignable to custom roles. **`viewer` now formally holds `audit.read`** —
  this reflects access it already had, since the full activity-log listing,
  search and export endpoints were never gated.

  As part of this, the SIEM integrations panel in Settings → Integrations stops
  showing "failed to load" for everyone except tenant administrators: listing
  SIEM forwarders was requiring the *write* permission.

- **Buttons that 403'd on click.** A number of controls were gated on a
  different permission from the route behind them, so the button was enabled and
  the action failed: Scopes create/edit/delete, CMDB sync and pull, retention
  policies, audit alert rules, spreadsheet import, sensor registration and
  configuration, job retry/cancel, scheduled scans and the Devices actions.
  Several were also gated *too strictly* and were hiding controls that Security
  Administrators are entitled to use — Scopes and CMDB sync were invisible to
  that role entirely. Both directions are corrected, and a test now asserts each
  gate against the permission its route actually enforces.

- **The SSO group-to-role mapping editor** no longer renders an empty role
  dropdown for administrators who cannot list roles. Saving with that empty
  dropdown would have cleared the role from every existing mapping.

- **The invite dialog** no longer silently offers "viewer" as the only role when
  it cannot load the tenant's roles. It now says what permission is missing and
  blocks sending, instead of quietly sending the invitation with the wrong role
 .

- **Settings pages that advertised access nobody had.** Roles & Permissions and
  Security & SSO appeared in the settings menu for roles whose every request to
  those pages would fail, producing an error banner instead of a clear "you do
  not have access" notice.

- **Tenant member lists** now require the same `users.read` permission whichever
  endpoint they are read through; one of the two paths had no permission check
  at all.

- **An idle session now returns you to sign-in instead of a wall of errors.**
  After the access token expired, every request answered `401`, no silent
  refresh was attempted, nothing navigated, and each panel rendered its own
  "Couldn't load …" card with no indication that the session had ended. The
  JS-readable `csrf_token` cookie is the signal the frontend reads as "a session
  exists", and it gates the refresh attempt — but it was issued with the *access
  token's* lifetime, so it disappeared at exactly the moment a refresh was due,
  while the refresh token was still valid for another seven days. It now tracks
  the refresh token. The practical effect is that an idle user is silently
  refreshed rather than interrupted at all; when the session really has ended,
  both UIs land on sign-in with a message saying so.

- **The Dashboard's Discovery card counted one fleet out of two.** It read only
  the sensor list, so a registered discovery agent going offline could never
  appear there, and the platform interrogation agent — which is a row in the
  sensors table — was counted as a sensor. A tenant running two sensors and two
  agents read "3/3 sensors". The card now shows both fleets combined and breaks
  them out as "Sensors 2/2 · Agents 2/2": a passive network sensor and a
  command-driven agent fail in different ways, and one number hides which half
  is down.

- **Findings from frameworks you never activated no longer appear anywhere.**
  The engine deliberately evaluates every published framework so it can show a
  preview score before you activate one, and pairs that with a rule that the
  detail is only visible for frameworks you *have* activated. The read half was
  never built. A tenant with one activated framework saw four on Findings → By
  Framework; the Dashboard's critical-findings count was sourced entirely from
  an unactivated framework while the activated one had none; and the Posture
  page contradicted itself, its control grid showing one framework beside a Top
  Exposures panel dominated by another. Alerting was never affected — it had the
  check all along. Custom policies, which carry no licence, stay visible.

## [0.6.3] - 2026-08-14

> 0.6.0 and 0.6.1 were tagged but never released (builder-toolchain failures);
> 0.6.2 built all 18 images but its chart job could not start, so no chart or
> GitHub release was published and its **frontend images shipped a Caddy binary
> on Go 1.26.5**. 0.6.3 is the first release of this line, with that fixed.

### Security

- **The published frontend images shipped a Caddy binary on Go 1.26.5**, carrying
  `CVE-2026-39821` (privilege escalation via Punycode label processing) and
  `CVE-2026-46600` (DoS via DNS record parsing) — while every backend image at the
  same tag scanned clean. The frontends' `caddybuild` stage set
  `ENV GOTOOLCHAIN=local`, and `release-core.yml` overrides `GO_BUILDER_IMAGE`
  with a *floating* tag (`golang:1.26-alpine`), which was still serving 1.26.5.
  `validate-dockerfiles.sh` exempted these stages on the reasoning that they
  compile an unrelated module, so go.work's floor does not apply — true, and
  exactly why the problem was invisible: nothing could fail the build, only a scan
  of the published image showed it. Both frontends now pin the exact patch, and
  the validator's exemption now covers any stage compiling a Go binary that is
  `COPY`ed into a shipped runtime. Verified by building on a `golang:1.26.5-alpine`
  base: `GOTOOLCHAIN=local` reproduces a `go1.26.5` binary, the pin yields
  `go1.26.6`.

  The remaining `web-ui` findings are upstream and not fixable here: the pinned
  `caddy:2-alpine` digest is the current one and is still Alpine 3.23.5
  (`c-ares`, `curl`/`libcurl`), and Caddy v2.11.4 is the latest release, so its
  `x/net`, `x/text` and `grpc` CVEs have no version to bump to.

- **Service-to-service signature verification no longer accepts the pre-SEC-2,
  query-omitted message shape by default.** The rolling-upgrade fallback was
  ungated and permanent, which meant a signature captured from a request carrying
  *no* query string also validated for that same method, path, body and timestamp
  with **any** query string appended. Combined with the replay window the code
  already documents (the nonce is signed entropy, never recorded, so an exact
  replay succeeds until it ages out of the ±5m skew), one observed internal call
  became a five-minute window to re-issue it with attacker-chosen query
  parameters — undoing the hardening SEC-2 added. The fallback is now opt-in via
  `SERVICEAUTH_ALLOW_LEGACY_QUERY_SIGNATURE`, for the duration of a rollout only.
  A test replays a genuine captured signature to pin the behaviour in both
  polarities.

- **`SECURITY.md` now states two deliberate tradeoffs** rather than leaving
  researchers to rediscover them: token revocation fails open when the Redis
  denylist is unreachable, and internal calls have a ±5m replay window.

- **An asset's approval status is no longer supplied by the caller**.
  `CreateAsset` took `input.AssetStatus` verbatim, so a request could ask to be
  `monitoring` and get it — on manual create, spreadsheet import and CMDB pull
  alike (all three reach the same function) — and the discovery import endpoint
  honoured `auto_approve: true` from anyone holding `discovery.create`. The
  tenant's own approval policy was therefore advisory: bypassable by callers who
  supplied a status, and inapplicable to those who did not, since an asset on an
  auto-approve segment still queued. Approval is now evaluated server-side from
  the tenant's network segments through `shared/approval` on every ingestion
  path, `auto_approve` is gone from the wire, and the ingestion endpoint rejects
  any caller that is not an HMAC-verified internal service. Auto-approval has
  exactly one gate, unchanged and still off by default: the asset is on a network
  segment with auto-approve enabled.

### Changed

- **A discovery scan's findings reach inventory without a browser in the loop**
 . `cluster-sensor-service` mirrored a job's findings into the ingestion
  queue only when the job carried a `result_sink` probe option, which exactly one
  caller (Active Scan) ever set. Every other job's findings reached inventory
  only if the Discover wizard was still open to fetch them and POST them back —
  close the wizard and they were stranded, with no control anywhere to recover
  them. The mirror is now unconditional and the wizard's import step is gone; the
  results step reports where the findings went ("N found · X auto-approved · Y
  awaiting approval") and links to Discovery → Approvals. The now-inert
  `result_sink` option was retired rather than left as a switch that no longer
  switches anything.

- **A job's find count and its inventory outcome are reported as two numbers, not
  one.** Job progress counts `discovery_findings` while inventory materializes
  from `sensor_discoveries`, so a job could honestly report N findings and add
  zero assets with nothing reconciling the two. `GET
  /discovery/jobs/{id}/results` now carries a `materialization` block (queued /
  auto_approved / pending_approval / awaiting_processing) alongside the find
  count. It is omitted rather than zeroed when it cannot be read, so absent means
  "unknown" rather than "nothing".

### Removed

- **`POST /api/v1/inventory-service/discovery/jobs/{id}/import` is no longer a
  tenant API** and is out of the OpenAPI contract and the generated TypeScript
  client. It survives as an internal service-to-service transport only (see
  Security above). The only consumer was our own Discover wizard.

- Removed two tests whose entire body was an unconditional `t.Skip()` — one on the
  impersonation flow, one on revocation against a real Redis. Neither had any
  assertions, so neither could fail, and both made `grep` report coverage of
  auth-critical paths that did not exist. Replaced with notes recording what a
  real test would need to assert, so the gap is visible instead of disguised.

## [0.6.2] - 2026-08-14

> 0.6.0 and 0.6.1 were tagged but never released — every Go image build failed
> on the toolchain issue described under Security below. Neither published a
> GitHub release, chart or backend image. 0.6.2 is that release with the build
> fixed.

### Added

- **SSH assets are now scored.** Until now every SSH configuration reached risk
  scoring with nothing linked and stayed at 0 — "not assessed" — no matter how
  weak it was: the sensor captured SSH banners and full KEXINIT algorithm lists,
  but nothing mapped them onto crypto-configuration components, and the algorithm
  catalogue carried no SSH rows at all. This release adds **54 catalogue entries**
  (protocol versions, key exchanges, ciphers, MACs and host-key types, each with a
  cited assessment — CVE-2001-0361 for SSH-1, Logjam for `diffie-hellman-group1-sha1`,
  Sweet32 and SP 800-131A for `3des-cbc`, RFC 8332 / OpenSSH 8.8 for `ssh-rsa`) and
  maps observations onto them. A modern server (Ed25519 + Curve25519 + AES-GCM)
  scores **20 (Low)**; a legacy one (`ssh-rsa` + `dh-group1-sha1` + `3des-cbc` +
  `hmac-md5`) scores **82 (High)**.

  Where a capture saw both sides of the handshake, the negotiated algorithm is
  *derived* per RFC 4253 §7.1 (first client entry also on the server's list) rather
  than guessed from the server's preference — the two genuinely differ. Algorithms a
  server merely **offers** are recorded as inferred and do raise the score, because
  they are reachable by any client that asks for them; the component columns carry
  only measured values, so compliance predicates never fire on something that did
  not happen. **Expect SSH assets that previously showed no score to now show one.**

- **"Why this score" in the crypto-configuration drawer.** The platform already
  computed a citable reason for every score — `"diffie-hellman-group1-sha1 is weak
  and obsolete (catalogue risk 82)"` — and wrote it only to a server log. The drawer
  now names the component that set the score, shows each component's catalogue
  assessment and migration guidance, and marks whether it was **observed in use** or
  **offered only**, via a new `GET /crypto-configurations/{id}/components` (,
  closes). Explanations are recomputed from the catalogue rather than stored,
  so editing a catalogue row changes the explanation with no stale copy to
  invalidate.

### Fixed

- **Active Scan was a silent no-op for most assets, and never scanned SSH.** It
  built scan targets as `host:port`, which nothing downstream accepts — the
  in-cluster scanner rejects `:` as an illegal nmap character and the standalone
  sensor tries to DNS-resolve the whole string — so targets were dropped with only a
  log line while the asset had *already* been stamped `monitoring` with a fresh
  `last_scanned_at` and reported as scanned. It also hardcoded `Protocols: ["TLS"]`
  on ports 443/8443, so a host on port 22 was never probed even though both
  runtimes have had SSH probers all along. Targets are now bare hosts with the port
  travelling in the job's port list, protocols are derived from the asset's recorded
  configurations (falling back to well-known-port inference), assets are grouped by
  scan shape so widening coverage does not multiply probe work, and an asset whose
  scan never dispatches has its previous scan freshness **restored** rather than
  blanked.

- **Infrastructure lens rows show what they used to show again.** The rebuilt tenant
  UI had reduced the row to a risk chip, hostname, certificate count and a bare
  score; the one remaining sub-line was empty for sensor-discovered assets, so rows
  looked blank. Restored to the eight-segment Tier-1 spec — identity, location and
  environment, service, risk, crypto summary with per-protocol badges and a
  configuration count, certificates, and relative last-seen — with graceful
  degradation at narrow widths. The list endpoint now returns
  `crypto_implementation_count` and a per-protocol summary so badges render from one
  request instead of a per-row query.

### Security

- **Go toolchain bumped 1.26.5 → 1.26.6** across every `go.mod`/`go.work`, the
  pinned `GO_VERSION` in CI/nightly/images/snyk/api-contract, nightly's
  `golang:1.26.6-bookworm` container, and `tools/qa-platform/run.sh`. Closes six
  called stdlib vulnerabilities that were failing the `govulncheck` gate on every
  PR: GO-2026-6218 (`net/url`), GO-2026-6090 (`crypto/tls`), GO-2026-6089
  (`net/http`), GO-2026-6088 (`encoding/xml`), GO-2026-5972 (`encoding/asn1`) and
  GO-2026-5026 (`net/http`/IDNA).

- **Image builds pin `GOTOOLCHAIN` to the exact `go.work` patch instead of
  `local`.** The Dockerfiles set `ENV GOTOOLCHAIN=local` for hermetic builds,
  which means "use whatever patch the base image ships." When `go.work` moved to
  1.26.6 and the base still shipped 1.26.5, **every Core image build failed**
  with `go.work requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)`.

  Pinning the base image is not sufficient on its own — `release-core.yml`
  overrides `GO_BUILDER_IMAGE` via `--build-arg`, and the Docker Hardened Images
  registry publishes no exact-patch tag, only a floating minor one. The 62
  workspace-building Dockerfiles now set `ENV GOTOOLCHAIN=go1.26.6`, which
  provisions the required toolchain whichever base is substituted and still
  refuses a 1.27 bump (`auto` would follow one). The builder ARG defaults are
  pinned too, as defence in depth. `validate-dockerfiles.sh` now fails a
  workspace-building Dockerfile whose `GOTOOLCHAIN` is not the exact `go.work`
  patch — `local` and `auto` are both rejected, mutation-verified.

- **`GOTOOLCHAIN` is pinned to the exact `go.work` version instead of `local`.**
  `local` blocked 1.27 (correct) but also refused to provision the *sanctioned*
  patch, so the 1.26.6 bump broke every Go-touching make target — and `make
  session-init`, the documented bootstrap for a fresh clone — on any machine
  without that exact toolchain installed. `auto` is not the answer either: it was
  observed emitting `go: downloading go1.27.0`. An exact pin keeps the tripwire and
  provisions automatically. A second assertion (`GO_POLICY_LINE`) rejects a
  `go.work` that leaves the 1.26 line, so the pin cannot be walked forward by
  editing one file, and no path degrades to `auto`.

### Internal

These do not change product behaviour, but they restored trust in the checks that
guard it.

- **CI could report a green PR while running zero test jobs.** Change detection used
  a shallow clone plus a fail-safe that tested whether the base-SHA *variable* was
  empty rather than whether the base commit was *reachable*. When `main` moved
  between a PR being opened and its gate running, `git diff` failed to stderr, the
  changed-file list came back empty, every matrix job's condition evaluated false,
  and the run went green having tested nothing — most likely precisely during an
  active merge sequence. Now reachability is verified and the base fetched on
  demand, with fail-open as a last resort; 24 assertions cover both polarities. The
  same shape in `deploy-smoke.yml` was fixed too.

- **Seven guards that reported success while checking nothing.** `make audit` piped
  its registry audit through `| cat`, so the recipe's exit status was always `cat`'s
  — it printed `AUDIT FAIL` and succeeded, and the pre-commit hook inherited the
  blindness (two real failures were hiding behind it). `make enforce`
  announced completion after printing failures and counted absent linters as passes.
  The Dockerfile Go-version check had matched **zero files** since Dockerfiles moved
  to `ARG GO_BUILDER_IMAGE`, so Critical Rule #1 had no mechanical enforcement at
  all; it now checks 64 Dockerfiles. `session-init.sh` and `dev-dashboard.sh` tested
  `>= 1.26` where the policy is `== 1.26`, calling 1.27 "OK". The public-tree
  export's build gate skipped silently when Go was absent. The image vulnerability
  scan always reported 0 CRITICAL / 0 HIGH because it grepped `^CRITICAL` against
  Trivy's table output. Every repair is mutation-tested in both directions.

- **Inert-guard audit** — 14 findings, 12 proved by mutation, recorded at
  `docsv4/internal/operations/INERT_GUARD_AUDIT.md`.

## [0.5.8] - 2026-08-13

### Fixed

- **UI data-consistency sweep: 30+ discrepancies fixed across every section**
  (PRs–). A full-platform QA pass on a live install found the
  Dashboard, Inventory, Risk & Compliance, Discovery, Remediation and Settings
  pages disagreeing with each other because they read unreconciled sources of
  truth. Highlights, by what a user saw:
  - **A completed device interrogation no longer reports "0 assets /
    fully materialized"** while the rest of the UI shows its results.
    Interrogation results were processed twice into two discovery jobs (one an
    orphan that stayed `queued` forever) and the honest-reporting block scored
    the empty twin; the discovery job stamped by the executor is now reused,
    job "Found" counts derive from what actually materialized, and the jobs
    list shows which executor ran each job.
  - **Dashboard "critical findings" now shows the same number the Findings
    page shows.** It read inventory's crypto-risk rollup (0 critical) while
    Findings/Posture read compliance findings (4 critical). The hero, tile and
    lifecycle stage now read compliance-engine's severity counts. Config
    totals, the PQC tile and "monitored assets" were likewise aligned to one
    population each — pending-approval assets are excluded from "monitored,"
    and unclassified crypto configs surface as "not yet assessed" instead of
    being branded "on classical crypto".
  - **Framework cards no longer say "0 controls" under a real score** (missing
    controls join), and a framework with open findings can no longer preview
    as "100% / 0 failing" without disclosure — cards now carry an
    open-findings count; findings from published-but-unactivated frameworks
    bucket under their real framework name instead of "Other / retired
    controls".
  - **The Posture control grid no longer silently drops findings** whose
    subject is a certificate or crypto configuration (15 of 19 on the QA
    tenant) — they roll into a labeled row and grid totals reconcile with the
    scorecards; findings show object names instead of truncated UUIDs.
  - **The certificate Ownership filter partitions the whole set** (an
    "Unknown" option exists; no cert vanishes from all buckets), TLS/SSH
    sub-lens counts match the rows shown, unassessed configs group as "Not
    assessed" rather than "Strong," weak-crypto badges show *why* (e.g.
    "Certificate missing SCTs"), CA certificates are credited with the
    deployments of the leaves they issued instead of showing "Unassigned,"
    and raw `/32` masks and `"QUIC v1 ()"` artifacts are gone.
  - **Usage & Limits stops calling a zero cap "unlimited"** (only −1/absent
    means no cap), platform-provided in-cluster agents no longer count against
    the tenant's own sensor usage, and the features endpoint reports the true
    active-framework count.
  - **The About page no longer shows "Degraded" on a healthy install:**
    pcap-processor and tenant-health-service ran with `USE_MTLS=true` but
    never opened the :8443 mesh listener every other backend opens; both now
    use the shared dual-listener bootstrap.
  - **Notification bell titles are human** ("Discovery job completed", not
    "[medium] job_completed") — producers' composed titles were being dropped
    in the NATS→HTTP conversion; sensor drawer labels per-interval vs total
    discoveries honestly; the Command Center fleet tile includes device agents
    so it can't contradict the Sensors & Agents header.

- **Asset drawer: hostname no longer wraps mid-name.** The identity block shared
  a row with the drawer's action buttons, leaving it a narrow column in a 500px
  drawer — any real FQDN broke across lines. Actions now sit on their own row
  above the identity block, which gets the full drawer width.
- **Active Scan on an asset now confirms it started.** The drawer button
  dispatched the scan job correctly, but the work happens asynchronously in the
  discovery pipeline, so nothing in the drawer changed and the click read as a
  no-op. It now raises a success (or failure) toast, matching Discovery →
  Active Scan.

## [0.5.7] - 2026-08-13

### Security

- **Device interrogation no longer collects key material.** Collectors assigned
  whole vendor API response objects into asset metadata, so every run persisted
  whatever the vendor returned alongside the configuration being inventoried. A
  single UniFi interrogation stored the controller's mesh PSK, per-device auth
  and vwire keys, syslog keys, the SMTP relay password and the operator's email
  address — roughly 350KB per run, none of which any consumer ever read.
  FortiOS was equivalent: `vpn.ipsec/phase1-interface` carries `psksecret`, the
  tunnel's pre-shared key, and `certificate/local` carries `private-key`.

  Every collector now projects the vendor response onto an explicit list of the
  fields the platform actually uses, so the material is discarded at the point
  of collection rather than stored and filtered afterwards. Where a device can
  be asked more narrowly it now is: Cisco interrogation requests
  `show running-config | include ssl cipher` instead of the whole
  `| section ssl|crypto`, which returned `crypto isakmp key <PSK>` for lines the
  parser never read — those keys are no longer transmitted off the device at
  all. Full `show version` transcripts are no longer retained, and the MySQL
  settings sweep is bounded to a named set rather than
  `LIKE '%ssl%' OR '%tls%' OR '%encrypt%'`.

  As a backstop, every interrogator dispatched through the shared registry is
  wrapped in a redaction pass that removes secret-looking fields by name, so a
  collector added later cannot skip it. Cryptographic-posture names (`key_size`,
  `key_exchange_algorithm`, `public_key`, `host_key_fingerprint`) are explicitly
  exempt — the guard must not eat what the product exists to report.

  Cloud discovery was audited and needed no change: AWS, Azure and GCP all map
  typed SDK or JSON-tagged structs field by field, which discards unknown fields
  structurally, and key discovery reads metadata only (AWS KMS keys are
  non-exportable, Azure is read through the Key Vault management plane).

  **Existing stored results are not retroactively scrubbed.** Interrogation jobs
  run before this change still hold their original payload in
  `device_jobs.results`.

### Fixed

- **Device interrogation results now reach inventory.** `CreateDiscoveryFinding`
  omitted `tenant_id` from its INSERT while the column is `NOT NULL`, so every
  finding insert on this path failed at the database. Callers logged the error
  and continued, which meant device interrogation produced discovery targets and
  zero findings — for every job, since the path was introduced. The failure also
  skipped the `sensor_discoveries` write that follows it, so one broken
  statement additionally disabled network classification, auto-approval and
  auto-import for interrogated assets.

  A job's asset count was read back out of the raw stored payload rather than
  from anything persisted, so a run that materialized nothing still reported
  "completed, N assets discovered". Result processing now records a per-asset,
  per-stage outcome onto the job, and the UI shows "discovered" and "into
  inventory" as separate figures so the two claims can disagree visibly.

- **A sensor whose registration failed no longer runs silently doing nothing.**
  Registration was attempted exactly once at startup, and a failure was logged
  as a warning immediately followed by `Sensor started successfully`. An
  unregistered sensor cannot submit anything, so the process captured packets on
  every worker and reported none of it — for hours, with logs that read as a
  healthy start.

  Registration now retries on its own, 30s doubling to a 15-minute ceiling, so a
  control plane that restarts mid-install needs no intervention. A *rejected*
  registration is treated differently: a consumed or invalid key returns the same
  answer forever, so the sensor refuses to start and quotes the platform's own
  reason and how to get a new key, rather than looping. 408/425/429 are
  explicitly retryable — treating "not now" as "never" would turn a rate-limited
  restart storm into a fleet that gave up for good. The startup banner no longer
  claims success while unregistered, and repeats the warning every 10 minutes.
 

- **The trust-bootstrap prompt no longer offers certificates that can never
  work.** It showed whatever certificate the platform presented and pinned it on
  acceptance, without first checking the certificate was valid for the host being
  connected to. Against a platform whose TLS secret was missing — so its ingress
  controller served its own placeholder — an operator was shown a fingerprint,
  accepted it, and the agent still could not connect: hostname verification runs
  *before* chain building, so no pinned anchor can rescue a name mismatch. The
  operator had completed what looked like a security step and got nothing, with
  no way to tell a real CA from a placeholder by reading a fingerprint.

  The agent now refuses before prompting, names what the server is actually
  serving, and says the platform's TLS is misconfigured. The same refusal applies
  on the unattended `--ca-fingerprint` path, where a correct fingerprint proves
  the operator has the right CA but says nothing about whether the server is
  serving the right certificate. A correctly-named private-CA platform still
  prompts and pins as before.

- **TLS-over-TCP connections record their protocol version.** They were reaching
  `external_connections` with a cipher suite and a full certificate chain but
  `protocol_version` NULL. `protocol_version` is what `isWeakProtocol` reads, so
  a TLS 1.0/1.1 connection could not be detected or scored at all.

  Two causes. sensor-manager's discovery envelope writes `version`,
  `cipher_suite` and `key_size` unconditionally, whether or not the sensor
  populated them, and discovery-processor's flatten let the outer value win
  unconditionally — so `"version": ""` erased the version the TLS enricher had
  just measured. An empty value carries no information and no longer beats one
  that does; a bool `false` is deliberately still an answer rather than an
  absence. Separately, the enricher now reports the version it negotiated instead
  of the (often empty) version of the passive observation that triggered the
  probe.

- **`pending_sensor_registrations.created_at` is set.** Every registration
  created through the web UI carried `0001-01-01 00:00:00+00`: the handler builds
  the model without it and the INSERT listed the column, so Go's zero time was
  written verbatim. Nothing surfaced it — `expires_at` is computed independently
  so expiry kept working, and the `expires_at > created_at` CHECK is satisfied
  trivially by year 1. The column already carried `DEFAULT now()`; it is no
  longer overridden, so the database owns the stamp and the next caller cannot
  forget it. No schema change.

### Added

- **Interrogation job detail.** Clicking a row on Discovery Jobs or Job Logs
  opens the run: execution timeline, per-stage pipeline counts, de-duplicated
  processing errors, and the discovered assets with their negotiated TLS
  version, cipher suite, key exchange, key size and full certificate detail.
  `GET /jobs/{id}/results` previously returned a fixed empty response and had no
  caller; it now serves a projected, secret-scrubbed view of the stored payload.

  Assets carry a `crypto_observed` flag, shown as a **not probed** marker. An
  asset listed by a device's management API but never given its own handshake
  has *unknown* posture rather than clean posture — the same distinction as a
  risk score of 0 meaning "not assessed".

- **Discovery agents can be removed.** A device agent could be registered but
  never deleted: the tenant-facing `/agents` group had exactly one route, `GET`.
  `device_agents.deleted_at` and its `deleted_at IS NULL` filters had shipped
  with the table, so the soft-delete model was designed and simply never
  implemented. `DELETE /agents/{id}` now completes it, gated on
  `discovery.manage` — the permission this service's other destructive routes
  already use, rather than a new one that would let a role delete the devices an
  agent interrogates but not the agent. One transaction: soft-delete, revoke the
  agent's certificates, release its queued jobs back to the unassigned pool, and
  fail the ones nothing can run.

  Queued jobs are released rather than discarded so the in-cluster worker or
  another agent picks them up, but a job that names no device cannot be released:
  `device_jobs`' `valid_job_assignment` CHECK permits an unassigned interrogation
  job only when it carries a `device_id`, because that is how an unassigned job's
  target gets resolved. Those are failed with their own message. Jobs already
  **in progress** are failed rather than re-queued — the deleted agent will never
  report, and re-queueing could run an interrogation against a live device twice.

  Deleting an agent does not uninstall it; the binary keeps running on the
  operator's host. That already failed closed and now stays that way under test —
  every agent-outbound path resolves the agent with `deleted_at IS NULL`, so a
  deleted agent's polls are answered 404 and it receives no jobs and no
  credentials. The 404 is documented in the agent deployment guide so it reads as
  the intended outcome rather than a network fault.

### Changed

- **Discovery agents are listed as themselves, not as sensors.** Agents and
  sensors shared one sensor-shaped fleet table whose columns include *Segment*
  and *Assets found* — neither of which a discovery agent has — so an agent row
  was mostly empty, while the fields an agent does have had nowhere to go.
  Discovery → Sensors & Agents now renders a separate **Discovery agents** table:
  name and description, host address (with the full multi-homed inventory and
  prefixes on hover), what the agent may interrogate, when it last ran a job and
  how many it has run, version, and status. Sensors keep their own table
  unchanged.

  The listing query was extended to match: it had never selected the agent's
  `description`, never joined `agent_addresses`, and exposed no job history at
  all — every one of those already existed in the database. Addresses are
  rendered with SQL `host()` rather than a text cast, which would append the
  prefix and never match a bare-IP comparison downstream.


## [0.5.6] - 2026-08-12

### Security

- **Agent/sensor mTLS now fails closed by default.** `AGENT_MTLS_REQUIRED`
  defaulted to `false`, so any deployment that did not explicitly enable it
  accepted sensor and discovery-agent traffic with no authentication at all —
  the agent UUID in the request path was the only credential. That UUID is what
  the tenant binding keys off (`SELECT tenant_id FROM sensors WHERE id = $1`),
  and UUIDs are not secrets: they appear in URLs, logs, API responses and
  support tickets. Anyone who knew one could submit discoveries into that
  tenant's inventory, correctly attributed. Both `sensor-manager` and
  `device-interrogation-service` now default the flag to `true`, so absence of
  configuration means "authenticate agents" rather than "accept anyone".

  Turning enforcement off is now an explicit, inspectable choice. The chart
  states `AGENT_MTLS_REQUIRED: "false"` on the agent-facing backends whenever
  `agentMtls.enabled` is false, rather than leaving the variable absent — the
  previous silence would now fail closed against the *mesh* certificate, whose
  CN can never match an agent id, locking every agent out. Compose dev
  opts out the same way. Chart behaviour is unchanged in both modes; what
  changes is that an unconfigured or hand-rolled deployment is no longer
  silently open.

### Added

- **Agents report every address they hold, not just one.** A capture host is
  routinely multi-homed and may watch several segments at once, which a single
  scalar address cannot describe. Sensors and discovery agents now report their
  full address inventory — interface, address and prefix — on every heartbeat,
  into a new `agent_addresses` table. `ip_address` remains the *primary*: the
  address the agent's kernel uses to reach the platform. One table serves both
  runtimes (paired nullable owner columns plus a CHECK, so real foreign keys and
  "exactly one owner" both hold), because the fleet UI already merges them and
  forking here is how the two drift apart. The sensor drawer lists every address
  once a host has more than one, marking the primary.

- **Discovery agents have an IP address at all.** `device_agents` had no such
  column, so the operator was required to type an expected address at enrollment
  that was then silently discarded, and the fleet list showed agents with no
  address forever. Agents now self-report theirs like sensors do, and it is
  surfaced in the fleet list and the platform-admin Fleet view.

- **The default admin credentials are documented.** `INSTALL.md` and the
  platform administrator guide now state both seeded accounts, the default
  password, and the forced first-sign-in rotation. Previously the rotation was
  described but the credentials themselves appeared in no customer-facing
  document, leaving a fresh install with no published way in.

### Changed

- **Running a sensor or discovery agent with no arguments is the install
  path.** Both binaries now open the configuration dialogue (with verbose
  logging on) on a fresh host, and the discovery agent starts when setup
  finishes instead of printing a command to run by hand. The dialogue steps
  aside for an existing config file, `CONTROL_PLANE_URL` / `PLATFORM_URL` in
  the environment, `-register`, a non-terminal stdin, or an explicit
  `-interactive=false`. Verbose is three-state: an absent `verbose:` key
  leaves the default alone, so only an operator's explicit choice quiets it.
  `term.IsTerminal` replaces a `ModeCharDevice` check that treated
  `/dev/null` as a terminal and hung the first prompt under a service
  manager.

- **Sensor enrollment cross-checks the expected IP honestly.** The operator's
  expected address is still collected and is now compared against the enrolling
  sensor's self-report, logged on every registration and rejected when
  `RequireIPValidation` is on. The comparison against `c.ClientIP()` is gone: it
  could never work behind an ingress or NAT, and its escape hatch was a stub
  (`isIPInSameSubnet` returned `ip1 == ip2`), so enabling enforcement rejected
  every registration in any Kubernetes install. This is a mistake-catcher, not
  an authentication control — authentication is the per-agent client
  certificate.

- **Seeded platform-admin accounts moved off the company domain.** The two
  default administrators are now `su_admin@vistaplatform.invalid` and
  `admin@vistaplatform.invalid` (were `…@vistasecurity.io`). Every install
  shipped two accounts whose addresses were deliverable to a real mailbox;
  `.invalid` is reserved by RFC 6761 and can never resolve, which is the
  correct shape for an identifier that is not meant to receive mail. Existing
  deployments **rename in place** on the next upgrade — the seed keys on the
  stable account ids, so a rotated password and the rest of the account survive
  and no duplicate row is created. Consequence: password-reset mail to a seeded
  admin does not arrive; rotate at first sign-in and create your own
  administrator under a real address (**Staff & Access → Staff**).

- **Every tenant-isolation RLS policy now states `WITH CHECK` explicitly.**
  `invitations` and `legal_acceptances` were the last two declared with the
  older `DO $$ … EXCEPTION WHEN duplicate_object` form at their own tables, and
  that form emits `USING` only. **This is a legibility fix, not a security
  fix** — Postgres reuses the `USING` expression as the new-row check when
  `WITH CHECK` is omitted, so those two policies were already rejecting
  cross-tenant writes, verified against a real Postgres. The inconsistency was
  worth closing anyway: it is the sole reason an internal audit reported a
  cross-tenant write hole that did not exist, and nobody auditing a policy
  should need to know the fallback rule to know what it enforces. The
  `DO/EXCEPTION` form also cannot *update* an existing policy — it hits the
  duplicate and silently keeps the old definition — which is why both sat
  unchanged across several releases. `TestIntegration_RLS_EveryTenantPolicyHasWithCheck`
  reads `pg_policy` and fails if any `*_tenant_isolation` policy omits the
  clause, so a third cannot appear silently.

### Fixed

- **Platform SSO providers can once again exist per purpose.** `schema.sql`
  DROPped `unique_platform_provider_type UNIQUE (provider_type)` early in the
  file and re-ADDed it 5,000 lines later in the constraint section, so the ADD
  always won and the provider_type-only uniqueness survived every apply. That
  made's one-row-per-`(provider_type, purpose)` model unrepresentable — a
  tenant-signup Google app and an admin-login Google app could not coexist.
  The retired constraint is gone and `uq_platform_sso_provider_type_purpose`
  is the only uniqueness on the table.

- **Nine tables were unreachable on every fresh install.** `schema.sql` granted
  the application role its privileges with `GRANT … ON ALL TABLES IN SCHEMA
  public`, from a block sitting in the middle of the file. Postgres expands
  `ON ALL TABLES` once, against the tables that exist at that instant — it is
  not a standing rule — so the nine tables created further down the file
  (`alerts`, `alert_events`, `alert_framework_score_snapshots`,
  `legal_acceptances`, `legal_documents`, `notification_digest_queue`,
  `platform_in_app_notifications`, `platform_maintenance_windows`,
  `tenant_alert_settings`) received no privileges at all. `ALTER DEFAULT
  PRIVILEGES` did not cover them either: it applies only to objects created by
  `crypto_user`, and only after it runs.

  Because `serviceRls` defaults to on, services connect as the NOBYPASSRLS
  `crypto_app` role, and the chart's `schema-migration` Job applies the file
  exactly once on install. A brand-new install therefore answered `permission
  denied for table …` across Remediation → Alerts, the notification digest
  queue, the platform-admin operator inbox, and the Terms/Privacy acceptance
  write on the signup path. Applying the schema a second time masked the fault
  entirely — by then the tables existed when the grant ran — which is why it
  went unnoticed. The same ordering also cost `crypto_bypass` its deliberate
  cross-tenant read on `mv_location_finding_summary`.

  The blanket grants now form the last block of the file, after every
  `CREATE TABLE`, with the deliberate matview narrowings following them so they
  still take effect. Two guards keep the shape from regressing:
  `scripts/audit-schema-grant-order.mjs` (in `make audit`, so it runs in the
  pre-commit hook) fails if any relation-creating statement lands after the
  grants, and `TestIntegration_Schema_SingleApplyGrantsEveryRelation` applies
  the schema **once** into a throwaway database and asserts every table, view
  and sequence is reachable.

- **Scheduled device interrogations reach an agent with credentials.** A
  schedule creates its job without any, which the in-cluster worker never
  noticed because it re-reads and decrypts credentials from the device row and
  ignores the job payload. A device agent has no database, so the same job
  would have authenticated with nothing. Credentials are now resolved from the
  device at dispatch, alongside the address, and a device with none fails the
  job with a clear reason instead of being handed over unrunnable.

- **A sensor's recorded IP address is now the sensor's, not the last network
  hop's.** Every heartbeat overwrote `sensors.ip_address` with `c.ClientIP()`,
  so on any clustered install the stored address was whichever Kubernetes node
  happened to receive the packet — kube-proxy SNATs to the receiving node under
  `externalTrafficPolicy: Cluster`, long before Traefik sees the connection, and
  `X-Forwarded-For` carries that same wrong value. A sensor on `192.0.2.173`
  displayed as `192.0.2.10`, and the value drifted between nodes beat to
  beat. Registration had always been correct; the first heartbeat destroyed it.
  The address is now self-reported in the heartbeat body, which is the only
  place it is knowable. Sensors that do not report one leave the stored value
  untouched rather than blanking it.

- **The sensor picks its address by route, not by scanning interfaces.**
  Detection returned the first non-loopback IPv4 in OS-defined order, which on a
  multi-homed host — routinely a Windows box with Hyper-V, WSL, or VPN adapters
  — is often a virtual adapter rather than the NIC carrying platform traffic. It
  now asks the routing table which local address would reach the control plane
  (a UDP connect that sends no packets), falling back to the old scan. An
  operator-pinned `SENSOR_IP_ADDRESS` is still honoured verbatim; an unpinned
  address is re-derived each heartbeat, so a host that changes network corrects
  itself instead of reporting where it was at startup.

- **A sensor that cannot determine its address says so instead of claiming
  loopback.** Registration substituted the literal `127.0.0.1` to satisfy a
  required field. The field is now optional and an unknown address is recorded
  as NULL — a confident falsehood would have pinned the sensor to loopback
  permanently once the platform began trusting the self-reported value.

- **Dead discovery agents no longer show as online.** `device_agents.status` is
  hard-coded `'active'` at enrollment and nothing ever rewrites it — unlike
  sensors, which have a reaper — so the fleet list rendered a green dot for an
  agent that had not checked in for days. Liveness now also requires a recent
  heartbeat, using the same dwell as the `discovery_agent_offline` alert so the
  list cannot contradict an alert an operator just received.

- **Stale browser caches can no longer pin users to an old web-ui build.** The
  web-ui Caddyfile served `index.html` with no `Cache-Control`, while `*.js`
  was `immutable, max-age=1y` — so after an upgrade, browsers that had
  heuristically cached `index.html` kept loading the previous bundle from
  cache indefinitely, silently running an old UI against the new API. Now only
  the content-hashed `/assets/*` output is immutable; `index.html` and
  unhashed public files (`/theme-init.js`, favicons) revalidate on every
  navigation. The admin-ui matcher was tightened the same way.
- **Editing a network segment from a client that omits
  `auto_approve_discoveries` no longer silently disables auto-approval.** The
  update API bound the field as a plain `bool`, so any request without it
  wrote `false` — the stale-bundle failure above did exactly that on every
  unrelated segment edit, wiping the toggle and leaving all discoveries stuck
  pending. The field is now optional with keep-current-on-omit update
  semantics (matching `is_active`), pinned by DB-integration tests.

## [0.5.5] - 2026-08-12

### Changed

- **Release agent binaries carry their version in the filename** —
  `crypto-sensor-<os>-<arch>-<version>` (extension preserved on Windows), so a
  downloaded binary states its release on disk instead of only when executed.
  The version rides at the end, so name-prefix download globs keep matching;
  `SHA256SUMS` and its signature cover the versioned names. Local `make`
  builds keep their bare names.

## [0.5.4] - 2026-08-12

Isolation and observability hardening on top of 0.5.3: plain views over
RLS-protected tables no longer execute as their owner (closing a cross-tenant
read bypass for the app role), materialized-view refresh works again under the
role split, and agent versions now track reality on every heartbeat instead of
freezing at registration.


### Security

- **Views over RLS tables no longer bypass tenant isolation.** A plain view
  executes with its owner's privileges, and the owner is exempt from RLS — so
  ten views over RLS-policied tables (`v_ci_inventory`,
  `tenant_health_summary_view`, `user_tenant_permissions`,
  `active_resource_alerts`, the AWS cost summaries, and others) were
  cross-tenant read paths for the tenant-confined `crypto_app` role. All now
  carry `security_invoker = true`, so the caller's RLS context applies through
  them exactly as on the tables. The three cross-tenant materialized views
  (which can carry neither RLS nor `security_invoker`) are revoked from
  `crypto_app` outright; tenant reads go through new fail-closed wrapper views
  (`mv_location_finding_summary_tenant`, `mv_remediation_queue_tenant`) that
  scope by `app.tenant_id`. Integration tests pin the full view list and prove
  both isolation directions as the app role.

### Fixed

- **Materialized-view refresh works again under the RLS role split.**
  `REFRESH MATERIALIZED VIEW` requires ownership, which the app role doesn't
  have, so every `refresh_operational_views()` /
  `refresh_tenant_cost_summary()` call since v0.5.0 failed "must be owner" —
  logged as non-fatal and swallowed, leaving the remediation queue and
  location summaries permanently stale. Both functions are now
  `SECURITY DEFINER` (run as the owner), with EXECUTE locked to the app roles.
- **Enterprise CMDB sync reads run tenant-scoped.** `fetchCIsForSync` now sets
  tenant context (required now that `v_ci_inventory` enforces RLS), and the
  `apply-rds-migrations.sh` RLS verification checks the real partitioned
  tables instead of view names `pg_tables` can never match (it warned on
  every run) — plus asserts the partition-wrapper views are `security_invoker`.

- **Agent versions refresh on heartbeat, not only at registration.** A sensor
  or device agent whose binary was swapped in place kept its old recorded
  version forever; the version now rides every heartbeat and the platform
  updates its record when it changes (an agent reporting nothing leaves the
  stored value untouched, so older binaries cannot blank it). The in-cluster
  platform agents converge the same way: the system-sensor health sweep stamps
  each swept service's own `/health`-reported release version, so the seeded
  `system` placeholder resolves to the running release on the first sweep
  after an upgrade — no re-registration required.

## [0.5.3] - 2026-08-12

### Fixed

- **Agent binaries report their real release version.** Every sensor and
  device-agent ever shipped claimed the hardcoded `1.0.0`, so the platform
  could not answer "which of my agents predate a given fix" — acute after
  v0.5.1's trust-anchor repair left older agents broken in the default
  configuration. Release builds now stamp `main.Version` from the tag; an
  unstamped local build reports `dev` rather than impersonating a release.
  Two latent defects fixed en route: the sensor's registration payload sent a
  config-file version instead of the binary's, and the Windows build script
  stamped a misspelled symbol whose ldflags had never taken effect. In-cluster
  platform agents now report the chart's `SERVICE_VERSION` instead of
  `system`. Versions are recorded at registration; heartbeat refresh for
  in-place upgrades is queued as follow-up.

## [0.5.2] - 2026-08-12

Overnight hardening pass driven by running a real sensor against v0.5.1 and
auditing what it exposed: the schema residue left by the partition conversion
is retired for good, config-only upgrades finally restart pods, the approval
workflow tells the truth in its logs and its UI, and a cluster of RLS
stragglers is closed. Also the first release whose favicons match the brand.

### Fixed

- **Changing app config with `helm upgrade` now actually reaches running
  pods.** Backend pod templates (and web-ui, whose subPath-mounted
  `config.json` never refreshes in place) hash the rendered app ConfigMap into
  a `checksum/config` annotation, so Helm rolls the Deployments on any
  effective config change instead of reporting success while pods keep the old
  values in memory (stale `COOKIE_DOMAIN` after a `tls.dnsName` change broke
  admin login and mis-reported the platform-CA fingerprint). A no-op upgrade
  still restarts nothing. Consequence: a config-only upgrade rolls every
  backend — on single-node clusters see the CPU-surge caveat in the deployment
  guide.

- **The legacy-table residue from the partition conversion is retired.** The
  drained `network_assets_legacy` / `crypto_implementations_legacy` /
  `sensor_discoveries_legacy` tables (and the dead `crypto_configurations`
  table, whose only writer was an unrouted service) are dropped, and everything
  that still pointed at them is repointed at the live partitioned tables. That
  fixes four silent-empty defects on every install: Enterprise CMDB sync
  exported nothing (`v_ci_inventory` read empty tables), the remediation queue
  and location summaries were permanently empty (`mv_remediation_queue`,
  `mv_location_finding_summary`), and `external_connections.source_asset_id`
  could never persist (its FK targeted the empty legacy table — as did the FKs
  on `ssh_keys`, `crypto_applications`, `database_encryption_states`, and
  `asset_history`, all retargeted to composite
  `(tenant_id, id) → network_assets_partitioned`, which also makes cross-tenant
  asset references unrepresentable). `make audit` now fails if anything
  references a `*_legacy` relation again.

- **`(tenant_id, id)` uniqueness is actually enforced on the partitioned
  tables.** `network_assets_partitioned`'s primary key was created parent-only
  (`ALTER TABLE ONLY`), which leaves it INVALID with no per-partition indexes —
  uniqueness was never enforced and no FK could reference it;
  `crypto_implementations_partitioned` had no primary key at all. Fresh installs
  now build both correctly; upgraded clusters are repaired in POST-MIGRATIONS.

- **Source-IP → asset matching works.** `host(ip_address)` instead of
  `ip_address::text`, which renders the netmask (`10.0.0.5/32`) and therefore
  never equaled a bare IP: external connections from an inventoried source IP
  now link to the asset, and bulk-import dedup by IP actually dedups.

- **Sensor-discovered leaf certificates are linked to their crypto
  configuration.** `LinkCertificateToImplementation` writes the primary
  certificate into `crypto_implementation_certificates` with role `leaf`, which
  the table's `valid_certificate_role` CHECK rejected — the insert failed
  (warning-only) on every discovery path, so chain certificates linked while
  the leaf never did, and the expiring-certificate risk queries that join
  through that junction missed every sensor-discovered leaf certificate. The
  CHECK now accepts `leaf`/`primary`, and the schema-reapply integration test
  pins it. Found by verifying deferred-finding materialization end-to-end on a
  live install.

- **The discovery batch log tells the truth about pending assets.** The
  processor printed a hardcoded `0 asset findings` for external-only batches,
  which read as "the pipeline produced nothing" while other batches were
  creating assets whose certificates and crypto configurations are
  deliberately deferred until approval. Batch summaries now report internal
  findings split by monitoring/pending (noting the deferral) and say
  "external-only" when that is what the batch was.

- **The approval queue is discoverable from Inventory.** New discoveries land
  in `pending_approval` and are excluded from every Inventory lens until
  approved — previously nothing said so, and a fresh tenant saw sensors
  reporting into an empty Inventory. Inventory now shows a pending-approval
  banner (count + link to Discovery → Approvals), the infrastructure lens
  empty state names the queue, and the Approvals page explains that accepting
  materializes the deferred certificates/crypto and where per-segment
  auto-approval lives (Settings → Infrastructure).

## [0.5.1] - 2026-08-11

Three defects found by running a real sensor against a v0.5.0 install rather
than trusting a green pipeline. Each one independently prevented a default Core
deployment from collecting any data at all: a new tenant could not register a
sensor, a registered sensor could not talk to the platform afterwards, and the
reads that would have shown either problem returned 500 or silently empty.

### Fixed

- **Sensors no longer go silent after a successful registration.** On enroll
  the agents replaced the operator-approved edge CA with the platform's agent
  CA, which only signs the mTLS passthrough listener — and that listener is
  off by default. Every later heartbeat/discovery then failed the handshake.
  Both CAs are now kept (`MergeCAPEMs`), including on the live
  `SensorManagerClient.Register` path and on device-agent rotation.

- **Self-signup tenants land on the `community` tier instead of staying at 0
  sensors / 0 assets forever.** `createTenant` assigned no `subscription_tier_id`
  "until the user selects a tier", but no self-signup surface ever asks — every
  Core signup then hit `Sensor limit exceeded: 0/0` (HTTP 402) and could not
  collect data. New tenants get the community floor (overridable with
  `DEFAULT_SIGNUP_TIER`); `seed.sql` backfills existing NULL-tier tenants on the
  next seed run. Capacity checks still fail closed when a tenant has no tier;
  the denial now names that cause.

- **Queries that ran on the RLS-scoped pool with no tenant context work again
  after `serviceRls` defaulted on.** Sensor discovery-by-id returned 500, platform
  sensor roll-ups were empty, the offline reaper never marked sensors offline,
  certificate-expiry alerts never fired, the stale-asset detector processed zero
  tenants so nothing ever aged or archived, trial locks never engaged, agent
  registration-key reuse was only detected within a single tenant, and usage
  counters read 0 so capacity caps never tripped. Cross-tenant lookups now use
  the bypass handle; tenant-scoped counts use `WithTenantTx`. `countAssets` is
  wrapped the same way as the other counters (it was missed in the original
  sweep). None of these raised an error — Postgres filters rows rather than
  failing, so each surfaced as a wrong answer.

  The second pass caught `countAssets` and the stale-asset enumerator because
  both read `network_assets`, a `security_invoker` **view** over an RLS-protected
  partitioned table: RLS applies to the caller there just as on a table, but the
  view does not appear in the obvious `pg_class.relrowsecurity` inventory. The
  same is true of `sensor_discoveries` and `crypto_implementations`.

  Regression tests connect as the non-owner `crypto_app` role
  (`testdb.ConnectAsAppRole`); an owner-connection test cannot detect this class
  at all, which is why the suite stayed green throughout. Each new guard was
  mutation-tested against the reverted fix.

## [0.5.0] - 2026-08-11

The first release published from `VistaSecurity/VistaPlatform-Core`, and the
one intended for the repository going public. Tenant isolation is now enforced
by the database on a default install, agents can enroll against a privately
signed platform, and the platform-admin API is off the public host.

### Added

- **Agents can enroll against a platform whose certificate is privately
  signed.** Registration is itself an HTTPS call, so an agent facing a
  self-signed or internal-CA platform previously failed x509 before it could
  obtain its client certificate — and the `ServerCACert` setting that existed
  for this was unreachable, because all three clients gated their TLS
  transport on already holding a client certificate. Server trust anchor and
  client identity are now configured independently. The installer shows the CA
  the platform presents — subject, issuer, validity, SHA-256 fingerprint — and
  asks, on the SSH `known_hosts` model; `--ca-fingerprint` covers unattended
  installs, and with neither a fingerprint nor an operator the agent refuses
  rather than pinning an unapproved CA. Verification is never disabled. The
  platform shows the matching fingerprint under **Discovery → Sensors & Agents
  → Register** (and on the pending-registration dialog) so the operator has a
  reference value to compare against, over their authenticated browser session
  — without it, a trust prompt gets approved blind.

### Changed

- **Row-level security is enabled by default (`serviceRls.enabled: true`).**
  The schema puts a tenant-isolation policy on 241 tables, but a table owner
  bypasses RLS — so with the toggle off, an install that advertised row-level
  tenant isolation did not actually enforce it. Services now connect as a
  non-owner role by default. **Installs on an external or managed Postgres
  must set `serviceRls.enabled: false`** — the Job that grants the roles LOGIN
  renders only for the bundled Postgres — and the chart fails the render with
  that instruction rather than silently enforcing nothing.

### Fixed

- **CBOM artifact listings are scoped to the caller's tenant.** `GET
  /cbom/artifacts` relied on row-level security alone, and because service
  connections use the table-owner role, RLS was not the isolation boundary
  there — artifact metadata was enumerable across tenants.

### Security

- **`/auth-service/internal/` is denied at the edge on every host**, and the
  admin-plane audit now checks both polarities — that gated groups are denied,
  and that the deny swallows nothing public. Public branding and social-signup
  endpoints are declared exceptions so a Kubernetes install shows the real
  wordmark and provider buttons.
- **The password-change gate no longer authorizes by path suffix.** The check
  accepted any path ending in `/auth/me` at any depth; it is now anchored, and
  consolidated across all four middleware copies.

## [0.4.1] - 2026-08-10

### Fixed

- **Core `web-ui` image builds again.** The artifact-service removal left a
  stale `createArtifactServiceClient` import in frontend-v2's typed client
  registry, failing the `tsc` build in `release-core`. v0.4.0 published a
  source tag but no images, chart, or release; v0.4.1 supersedes it.

## [0.4.0] - 2026-08-10

The headline change is the removal of `artifact-service` — a breaking
simplification of the platform's distribution story — alongside a light-mode
visual refresh, admin-plane edge-audit hardening, and compliance score-truth
fixes.

### Changed

- **Light-mode canvas and theme-aware dashboard hero.** The tenant and admin
  UIs use an accent-tinted light canvas (`color-mix` from `--accent`) with
  cooled blue-greys; the dashboard hero uses per-theme `--hero-bg` /
  `--hero-border` / `--hero-glow-blend` so light mode is readable (dark stays
  pixel-identical). Brand presets: `vista-blue` active, `gold` switchable via
  `data-brand`.

### Fixed

- **Framework preview scores stay continuously true; the dashboard PQC number
  is adoption-only.** `EvaluateAsset` refreshes `tenant_framework_scores` for
  every published framework (a fully-passing framework produces no findings, so
  the old affected-only refresh left its card as "—"). Listing available
  frameworks enqueues a one-shot baseline reconcile when any published
  framework lacks a rollup. The dashboard PQC stat always uses `/pqc/summary`
  config adoption and no longer swaps to the PQC Readiness framework score on
  activation.

- **Platform branding and social signup work on Kubernetes installs again.**
  The admin-plane deny for `/auth-service/platform/` swallowed the public
  branding endpoints (`/platform/config`, `/platform/ui-config`) and the ee
  social-signup provider list (`/platform/sso-providers`) on the tenant host,
  so the login page showed the built-in fallback wordmark and signup rendered
  no provider buttons — silently, k8s-only (the compose gateway had no deny).
  The three routes are now declared `public_exceptions` and outrank the deny.
  The default platform name is now "Vista Platform" (was "VistaPlatform").

### Security

- **`/auth-service/internal/` is now denied at the edge on every host.** The
  HMAC-gated PAT-exchange endpoint was published on the public ingress with a
  leaked `INTERNAL_AUTH_SECRET` as its only barrier; its sole caller reaches
  auth-service in-cluster and never transits the edge.
- **The admin-plane audit now checks both polarities.** It previously verified
  every gated group is denied but never that the deny swallows nothing public —
  and its parser missed direct (non-group) route registrations and the
  `RequireInternalOnly` gate spelling. All three gaps are closed and pinned by
  regression tests; anonymous-public routes under a denied prefix must now be
  declared `public_exceptions` (tenant host serves them) or `admin_host_public`
  (admin host serves them, e.g. platform-admin login) or the audit fails.
  Two dead, never-implemented route-group shells in auth-service were removed.

### Removed

- **`artifact-service` removed entirely** — the in-product binary-distribution
  registry is gone (service, its 3 database tables, its OpenAPI spec and typed
  client, its admin-ui Catalog → Artifacts page and Tenant Overrides sub-view,
  its chart backend, and its release-pipeline entries). It stored only URL
  pointers, never binaries; the product's distribution path is signed GitHub
  Release assets (or `make build-sensor`). Half its API surface had no caller,
  and it exposed unauthenticated public `/downloads/*` endpoints. Backend Go
  services drop from 17 to 16 and the release image set from 19 to 18.
  `device-interrogation-service`'s `/downloads/agent*` routes (which proxied to
  it) are removed with it. Database tables `artifacts`, `artifact_audit_log` and
  `tenant_artifact_config` are dropped by the schema-migration Job on the next
  `helm upgrade`.


## [0.3.1] - 2026-08-10

Pre-publication polish for the public repository: the reader-facing surfaces
(docs index, changelog, release bodies, chart metadata) now survive scrutiny
without a docs-site renderer, and a PCAP ingest correctness fix.

### Fixed

- **PCAP TLS session dedupe no longer drops distinct SNI/certificate/crypto evidence**. Sessions sharing a server IP:port but differing in SNI, leaf cert, negotiated version, or cipher suite are preserved; identical evidence from different clients still collapses. Compliance reconcile coalescing now redelivers the owning JetStream message when the dirty flag remains after the follow-up budget, and certificate-change scoped reconcile fails on any partial target failure so work is not ACKed unfinished.

- **Public Core export no longer ships raw doc macros, scrub residue, or a broken cosign verify command**. Export renders known `{{ product.* }}`/`{{ provider.* }}` keys, carries the full 0.x changelog history without `` leftover paren groups, hard-fails new core-layer legacy `developer-docs/` links, and `release-core.yml` emits a pasteable cosign identity line.

## [0.3.0] - 2026-08-10

This release is the outcome of an eight-domain expert audit of the Core tree —
compliance verdicts, risk scoring, CBOM conformance, discovery truthfulness,
SQL and ingest performance, security hardening, the frontend, and the
first-install path — followed by two remediation waves. The audit's headline:
the architecture and plumbing were strong, but the domain-correctness layer
shipped confident wrong answers. This release repairs that layer.

### Fixed

- **The compliance verdict layer no longer fails compliant assets or passes
  failing ones**. Boolean measurements (PFS support, certificate-chain
  validity) were treated as "present" regardless of their value, so two
  best-practice controls failed on every asset including compliant ones. Seeded
  measurement predicates could not match the vocabulary the parsers actually
  emit (the no-PFS key-exchange forms the control exists for were unmatchable).
  The `key_size >= 2048` rule flagged every elliptic-curve certificate
  (P-256 = 256 bits) as weak; it is now algorithm-aware. The Critical SSLv3
  control missed connections recorded as `Unknown-0x0300`. Live evaluation and
  the materialized rollup disagreed on status for the same findings (preview
  said 100, summary said 0). Pattern rules ignored their case-insensitivity and
  `match_means_violation` flags; measurement severity ignored the control's
  baseline; certificate-expiry findings were reported up to 24 hours early with
  timestamps in the future. And Core tenants can now actually activate all six
  free frameworks — the seeded tier cap of 0 previously blocked five of them.

- **Discovered cryptography is identified truthfully**. The key
  exchange reported by a discovery was never linked to the catalogue — so a
  post-quantum or hybrid group (ML-KEM-768, X25519MLKEM768), which never
  appears in a cipher-suite name, was invisible to PQC readiness — and the
  TLS 1.3 "ECDHE" inference overrode the observed group, making every PQC
  endpoint look classical. Elliptic-curve keys were measured against the RSA
  modulus floor and reported Critical (83 false Criticals in a 132-host
  dataset). Ambiguous algorithm strings resolved to a guess via unordered
  fuzzy match — "RSA" landed on RSA-MD5, recording every RSA-authenticated TLS
  endpoint as MD5-signed, and an SSH version "2.0" matched "SSL 2.0". The
  classifier now takes an exact code match, else a unique in-category partial
  match, else leaves the component honestly unclassified. Unknown algorithms
  are no longer fabricated into the catalogue as "acceptable, risk 50", and the
  ingest INSERT now actually writes the symmetric/signature/hash component
  columns it always left NULL — several best-practice and PQC controls were
  silent no-ops without them.

- **One cipher-suite parser**. Three drifted copies (inventory,
  cbom-service, sensor) consolidated into `shared/cryptoparse`, emitting
  catalogue codes case-insensitively. Spaced protocol strings (`"TLS 1.2"`)
  now resolve against the catalogue — the RFC 8996 obsolete-protocol risk
  ladder had **never fired for sensor-recorded data** before this fix. Also
  repaired the Enterprise bundle's SSL patterns, and shipped predicate
  corrections as UPDATEs so they take effect on already-deployed databases.

- **Discovery records what was actually negotiated**. The passive
  TLS assembler recorded the client's best *offered* version as the negotiated
  one — TLS 1.2 connections were inventoried as 1.3 — because it never read
  the ServerHello; it does now, in both the direct and STARTTLS paths. The
  in-cluster Platform Sensor's prober adopted the shared probing core: it no
  longer reports valid chains as `untrusted_ca` (it never built an
  intermediates pool), no longer reports false `hostname_mismatch` for
  IP-address targets, emits canonical metadata so quality flags and the
  negotiated version survive downstream, and honors the job's requested ports
  instead of a hard-coded 443/8443/636 list. Passive-path quality flags are
  kept instead of computed-then-discarded, and the EV OID list gained the
  CA/B-Forum umbrella OID.

- **pcap-processor rewritten to report the truth**. Uploaded captures
  were parsed without TCP reassembly, reported TLS 1.3 as 1.2 (it never read
  `supported_versions`), extracted zero certificates, and emitted hex cipher
  codes. A new pure-Go TLS parser does per-flow, per-direction reassembly with
  byte and flow caps, extracts DER certificate chains, resolves IANA cipher
  names, and reads the real negotiated version. Session-based emission also
  fixed a direction bug that inventoried *clients* at ephemeral ports as
  assets.

- **The discovery ingest hot path is indexed and claim-safe**. The
  partitioned discovery table had no primary key, so every per-discovery
  status update sequential-scanned all partitions in its own transaction; it
  now has one, plus a partial index for the unprocessed-work poller, and
  processed-marking is batched. Discoveries are batch-claimed with
  `FOR UPDATE SKIP LOCKED`, so the NATS handler and the ticker no longer
  process the same rows concurrently. Asset matching uses indexable equality;
  auto-approval rules are fetched once per batch instead of once per
  discovery; and a failed external-connection upsert no longer marks the
  discovery processed (previously a silent, permanent drop). Missing indexes
  were added across the audit/history tables, and two materialized views with
  hand-written drifted risk ladders are regenerated from the canonical bands.

- **Row-level-security policies are indexable**. 237 tenant-isolation
  policies compared `(tenant_id)::text`, defeating every tenant index; the
  rewrite restored index use (385× on the CBOM list query) and partition
  pruning.

- **Compliance reconciliation scoped and coalesced**. A certificate
  change re-evaluated the whole tenant; it now reconciles only the assets that
  use the certificate, coalesces duplicate tenant passes, and skips no-op
  finding updates instead of churning rows. Also fixed a leaf-certificate link
  query that never bound its certificate id.

- **The chart's schema copy is byte-identical to the source again**.
  `charts/vistaplatform/files/schema/schema.sql` had drifted ~56 lines behind
  `scripts/database/schema.sql` — a CBOM storage migration never reached
  deployed clusters. Reconciled, and `make audit` now fails on any byte of
  drift.

- **Sensor internals deduplicated**. A stale ~4,000-line copy of the
  capture engine was deleted, certificate-chain validation is delegated to the
  shared implementation, and the known-bad-CA list was refreshed with
  dual-verified entries.

- **CBOM artifacts are schema-valid and scopes actually scope**.
  Artifacts declared CycloneDX 1.6 while emitting 1.7-only fields, so every
  certificate-bearing artifact failed `cyclonedx validate`; they now declare
  1.7, map non-enum protocol types to `other`, and are validated against the
  official schema in tests. Scope `exclude` clauses were silently ignored and
  most `include` fields dropped — the "Non-Dev/Test" system scope was
  equivalent to "All" — and unassigned certificates bypassed scoping entirely.
  All predicate fields now apply, `dependsOn`/`algorithmRef` emit real
  bom-refs instead of internal UUIDs, and the list limit and generation
  timeout are wired through.

- **Frontend correctness**. The risk-score ladder banded High at ≥60
  where the canonical bands say ≥70; it now matches the backend, preferring
  the server-computed level where present. Five visible "Spec'd — build
  pending" placeholder pages are filtered from navigation, and tier assignment
  — authorable but unreachable — has a UI action.

- **The first-install path survives being followed**. Installing
  published Core v0.2.0 from scratch showed `INSTALL.md`'s evaluate path
  stopping dead on a bare cluster (serviceMtls is on by default and requires
  cert-manager, which the docs did not list as a default prerequisite — the
  default stays on; the docs now say so). The chart also reissues its
  self-signed certificate when `tls.dnsName` changes — previously the old SANs
  were reused silently and Traefik served its default certificate while
  `helm upgrade` reported success.

### Security

- **Service-to-service HMAC signatures now cover the query string**.
  The canonical message signed only the path, leaving query parameters
  unauthenticated between services; the verifier accepts the legacy form
  during a rolling upgrade. Service-account token validation no longer runs
  bcrypt against every active account on every request (indexed hash lookup,
  then a single bcrypt confirmation). Overdue-ticket notifications publish
  before storing their dedupe key, so a failed publish is retried instead of
  silently suppressed for 24 hours. The compliance-reconcile worker's
  documented kill switch is actually wired, and its fan-out excludes
  soft-deleted tenants.

### Added

- **A demo dataset that shows the product**. The shipped seed dataset
  predated the Keys lens, PQC readiness, and risk distribution — 73 findings,
  one certificate, zero post-quantum algorithms. The new DemoCorp dataset
  models 132 findings across 8 network segments (two data centres, corporate,
  a post-quantum pilot, an OT plant floor) with real generated X.509 — ~100
  certificates, ~78 SPKI-deduplicated keys, and ~650 algorithm links — so
  every lens has something true to say.

- **Alerts joined the typed API contract**. The alerts surface is
  specced in OpenAPI and consumed through the generated client; the raw-fetch
  module is deleted.

### Changed

- **First-hour documentation rewritten around what exists**. Sensor
  registration is documented around the real flow (UI registration plus
  release binaries or a source build) instead of removed endpoints; pre-Helm
  EC2 deployment docs that executed scripts from a personal repository are
  deleted; the operator docs index leads with the supported install path; the
  chart's cosign verification command is runnable; and the README's service
  count is correct.

- **Documentation link integrity is enforced at zero**. Every broken
  relative link in the shipped docs layers was repaired and the audit ratchet
  floor is now 0, so a new broken link fails CI.

## [0.2.0] - 2026-08-09

### Fixed

- **Stale-asset detection reached no tenant onboarded through signup**.
  The job enumerated tenants from `asset_lifecycle_policies`, but that row only
  exists once someone opens Settings and saves one — so signup tenants were
  skipped and their assets never aged, while the UI showed the in-memory default
  (30-day warn / 60-day archive) and looked enabled. It now enumerates by "has
  assets"; an explicit `auto_archive_enabled = false` is still honoured. The same
  change fixes stale reads crashing on any asset carrying `tags`/`metadata` (raw
  jsonb scanned into a bare Go map), which also broke the stale lens.

- **The Keys lens errored on any key with a `key_usage` array or `metadata`**
  — `text[]`/`jsonb` scanned straight into `[]string`/`map`. Latent until
  the key producer landed; load-bearing now.

- **Stale legacy foreign keys broke `helm upgrade` once the junction tables had
  rows**. Four FKs on the `crypto_implementations` junctions targeted the
  empty `crypto_implementations_legacy`, so they could never be satisfied. One was
  dropped in POST-MIGRATIONS while still being re-`ADD`ed in the pg_dump body —
  fine on an empty database, and an aborted `schema-migration` Job on the next
  upgrade of any cluster that had written a row. All four `ADD CONSTRAINT`
  statements are removed and all four drops retained.

  Two of them had been silently blocking writes all along:
  `crypto_implementation_algorithms` (the ingest path swallows the link error, so
  that junction had **always been empty in production** — PQC readiness had
  nothing to classify) and `implementation_libraries` (`AttachLibrary`).

- **Risk bands disagreed between the badges and the counters**. Every
  risk badge banded High at `>= 60`; the dashboard distribution and the risk facet
  filter used `>= 70`. An asset scoring 60–69 rendered *High*, was counted
  *Medium*, and was dropped by the "High" filter. The summary also banded per
  crypto implementation and then counted distinct assets, so one asset with a 75-
  and a 30-scoring implementation was counted in **both** High and Low and the
  distribution could exceed 100%.

- **Post-quantum readiness could exceed 100% and called AES a migration target**
 . `/pqc/progress` summed per-algorithm-family counts over a
  per-implementation denominator, and decided "quantum safe" from an allowlist of
  primitives `{ae, hash, mac}` that omitted `block-cipher`, `stream-cipher` and
  `xof` — so plain AES128/AES256, RC4 and the SHAKE functions counted as needing
  PQC migration. An RSA key exchange alongside an AES-GCM cipher was reported as
  "symmetric safe".

- **The algorithm catalogue had OID, primitive and completeness errors**.
  ML-KEM entries sat on the AES OID arc rather than the NIST KEM arc, TLS/SSL
  protocol-version rows carried a `serverAuth` extended-key-usage OID that is not
  an algorithm identifier at all, and AES-CBC variants were typed as authenticated
  encryption. 21 missing algorithms were added and CycloneDX identity gaps
  (crypto_functions, classical/quantum security levels, curve) were filled. A
  guard test now pins the corrections and fails if any regress.

### Changed

- **Public release notes are no longer self-referential.** The export wrote
  "See the release notes at <this release's own URL>" into the public CHANGELOG,
  and the release workflow lifts that same section to use as the GitHub Release
  body — so the Release told the reader to go read the Release. The export now
  carries the real notes across from this file's matching section, with issue and
  PR references stripped.

- **Documentation and product descriptors reflect the above**. Notably
  `crypto-risks.md` documented additive scoring (+80/+60/+40/+20) that never
  existed, and the algorithm-taxonomy descriptor claimed every crypto-risk view
  joined to the `algorithms` table — true only as of this release.

- **Cryptographic risk scores are now derived from the algorithm catalogue**
 . A crypto configuration's `risk_score` is the `algorithms.risk_score` of
  its worst linked component (protocol version, cipher suite, key exchange,
  signature, symmetric, hash), so every risk number traces to a catalogue row a
  reviewer can open and correct — re-assess an algorithm and every affected
  configuration re-scores.

  Previously `algorithms.risk_score` appeared **only in `ORDER BY` clauses** while
  the displayed score came from hardcoded string matching, which emitted one of
  four fixed values. Two parallel opinions about how risky an algorithm is, and
  the uncited one won. The weak-crypto detector is still consulted for what a
  per-algorithm catalogue cannot express — chiefly key **size** (the SP 800-131A
  2048-bit RSA floor) — and the worse of the two wins, so the catalogue can only
  raise a score.

  **Scores become continuous across 0–100** instead of a fixed set, so
  well-configured services now score Low rather than 0. A score of **0 now means
  "not assessed"** — nothing resolved against the catalogue — which is
  deliberately distinct from "assessed as safe".

- **Risk severity bands are anchored to the CVSS qualitative severity ratings**
  — Critical ≥90, High 70–89, Medium 40–69, Low 1–39, Informational 0 —
  and are generated from a single definition consumed by both the Go label
  function and every SQL query, so the badge, the facet filter and the summary
  counters can no longer band the same score differently. No standards body
  publishes a 0–100 score for cryptographic configuration, so the score's inputs
  stay standards-anchored (NIST SP 800-57 / SP 800-131A / RFC 8996) while the
  banding follows the one published convention for the job.

  This was a no-op for existing data: scores only ever took four values, all of
  which band identically under both ladders, so no badge moved and the posture
  trend stayed continuous.

- **Post-quantum readiness classifies each implementation exactly once**
  into four mutually exclusive categories — needs-migration, PQC-ready,
  symmetric-safe and the new **unclassified** — so they sum to the total and the
  percentage is bounded by 100. Vulnerability is decided by a denylist of the
  Shor-breakable primitives (`signature`, `kem`, `key-agree`, `pke`) per **NIST
  IR 8547**, rather than an allowlist of "safe" ones that silently misclassified
  whatever it omitted. Any classical asymmetric component now makes the whole
  implementation quantum-vulnerable regardless of what else it uses.

  `/pqc/progress` and `/pqc/summary` derive from the same classifier, so the two
  readiness numbers the product reports can no longer contradict each other.
  `unclassified` is surfaced rather than folded into a safe or unsafe bucket, and
  counts against readiness — not knowing is not evidence of safety.

- **The cryptographic-key inventory is populated from certificate public keys**
 . The Keys lens read path had shipped without a producer, so the lens was
  structurally always empty. Keys are SPKI-fingerprint-deduplicated, metadata only
  — never key material.

<!-- The entries below shipped in 0.2.0 but sat under [Unreleased] when
     the tag was cut; recorded here post-hoc for the historical record. -->

### Changed

- **The seeded Terms of Service and Privacy Policy are real templates instead of
  Lorem ipsum**, and `INSTALL.md` now tells operators to replace them.

  Nothing previously told an operator the text was placeholder, so a Core
  deployment could go live with users accepting Lorem ipsum. The templates carry
  the structure that actually matters — authorization to scan, the disclaimer
  that findings are not a guarantee of compliance, discovery data as potentially
  personal data, retention, sub-processors, data-subject rights — with
  `[BRACKETED]` blanks and a banner stating they are not legal advice.

  They are written from the **operator's** side on purpose: VistaPlatform is
  self-hosted, so the organization running it is the service provider and the
  data controller, and these are their terms with their users. The software
  authors neither operate the instance nor receive data from it, which the
  privacy template says explicitly.

  The seed statement was also restructured. The body used to be written out
  **twice** — once as the column value, once inside `sha256()` — so editing one
  copy and not the other produced a row whose content hash silently disagreed
  with its own text. The body now appears once and the hash derives from it in
  the same statement. Verified against a real Postgres: applies twice cleanly,
  and each stored hash matches a sha256 of the source file computed outside the
  database.

- **Security and conduct contacts are now `product@vistasecurity.io`**, and the
  operator docs stopped promising things that do not exist for a Core user: a
  PGP key at a `security.txt` URL, a support phone "on your contract", and a
  one-business-day acknowledgement that contradicted SECURITY.md's three days.
  Those docs now point at SECURITY.md as the authoritative policy.

### Fixed

- **Docker cleanup now scopes to the Compose project name from `.env` /
  `--env-file`.** Follow-up sweeps after `docker compose down` previously fell
  back to the checkout directory basename when the shell had no
  `COMPOSE_PROJECT_NAME`, so a differently named stack could be swept by
  accident. The shared helper now reads the env file the same way Compose does.

- **The nightly secret-detection gate is green again.** Gitleaks flagged
  `reg-key-9d3f5c8a` in `shared/agentcreds/contract_vector.go` as a
  `generic-api-key`. It is the frozen contract test vector: the platform
  serializer and the agent parser live in separate Go modules that cannot import
  each other, so one fixed (JobID, Secret, Envelope, Credentials) tuple *is* the
  contract between them, and `Secret` has to be constant or the vector proves
  nothing. It grants nothing and decrypts exactly one hard-coded envelope
  committed beside it. Allowlisted by path, matching the existing entries.

### Added

- **Pre-built sensor and device-agent binaries, attached to every Core release**,
  and a GitHub Release to attach them to — `release-core.yml` previously left the
  public repo with a bare tag and no release page at all.

  Anyone can build both from source, and should be able to, which is why the
  source is here. But requiring a Go toolchain and libpcap headers before you can
  look at your own network is a bad first hour, and most people evaluating this
  will not compile it.

  Seven build jobs, because one Linux box cannot produce them: the sensor links
  libpcap (`CGO_ENABLED=1`) on Linux and macOS, so those build natively per
  platform — linux/arm64 on an arm runner rather than dragging in a cross
  toolchain plus a cross libpcap, and darwin on real macOS. The Windows sensor is
  CGO-free and cross-compiles, as does the device agent for all five of its
  platforms from a single job.

  A `SHA256SUMS` file covers every binary and is cosign-signed keylessly, so
  verification is two commands rather than one per file. The generated release
  notes carry the verification recipe and — because the sensor is **dynamically
  linked against libpcap** while the agent is static — the per-OS install line
  for it. Without that, a downloaded sensor fails with a loader error that never
  mentions libpcap.

### Security

- **Docker Compose and EC2-smoke Traefik configs now deny the same control-plane
  routes the Helm ingress already denied** ( /).

  Chart generation closed the `/internal/*` edge exposure and the admin-plane
  host split; the file-provider configs used by local compose and EC2-smoke
  still published both. `scripts/generate-traefik-config.mjs` now emits
  `deny-internal-plane` routers for every declared `admin_plane.internal_prefixes`
  entry in all topologies, and on multi-host (`gateway_routes_ui=true`) it also
  splits platform-admin prefixes — allow on the admin host, deny on the public
  API host, with the existing public exceptions at higher priority.
  `scripts/audit-admin-plane.mjs` now fails when those generated routers drift.

- **A sensor configuration captured verbatim from a live lab machine was
  shipping in customer-facing documentation.** `sensor/CONFIGURATION_AND_LOGS.md`
  contained a real registration key — an *enrolment credential* — plus a real
  sensor UUID and a private-subnet control-plane URL. It survived four publishes
  because none of it looks like a secret to a generic scanner: `REG-<hex>`
  matches no standard token shape.

  Replaced with obvious placeholders. Every other registration key in the tree
  was already a self-evident dummy (`REG-0123…`, `REG-deadbeef…`) and is
  untouched.

  Five other leaks of internal lab identity went with it — a `KUBE` default
  pointing at the maintainer's kubeconfig, the maintainer's cluster offered as
  an option in the public bug-report template, and three comments naming an
  internal cluster.

  Both classes are now **export gates** rather than scrubs: the export fails if
  internal hostnames/IPs or a high-entropy registration key appear in the public
  tree. Gates rather than automatic rewrites because there is no safe
  substitution — "which host did the author mean" is a judgement call, and
  silently rewriting an example is how you ship documentation that is
  confidently wrong. Both mutation-tested.

### Fixed

- **The teardown scripts no longer empty the whole Docker daemon.**
  `cleanup-docker.sh` ran `docker stop $(docker ps -q)`, `docker rm -f $(docker
  ps -aq)`, removed every custom network, removed every *dangling* volume —
  which, having just deleted every container, meant every volume on the host —
  and finished with `docker image prune -a -f`. `docker-manager.sh clean-all`
  did the same via `network/volume/image prune`, its "orphaned containers" check
  offered to delete every container on the machine, `clean-all-volumes.sh`
  stopped every running container twice, and `fix-deployment-issues.sh` ran a
  silent `docker system prune -f`. All of these ship in the public tree, where
  the machine on the other end is one we know nothing about.

  Every one is now scoped to the compose project label via the new
  `scripts/lib/docker-scope.sh`; `cleanup-docker.sh` gains `--images`,
  `--build-cache`, `--dry-run` and `--yes`, and leaves pulled base images alone.
  The one genuinely unscopeable operation, `docker builder prune` (BuildKit's
  cache is per-daemon), now asks before running and skips itself when there is
  no terminal. `scripts/audit-destructive-scripts.mjs` (strict in `make audit`)
  fails on any unfiltered removal or ungated builder prune reintroduced later.

- **`docker compose up` no longer dies halfway through on a machine that is
  already using a common port.** `env.example` moves published host ports into
  the 4xxxx range so the stack starts beside whatever else is listening, but
  twelve of them were never listed — Prometheus, Jaeger, the two OTLP receivers,
  and eight service ports — so each fell back to its bare compose default.
  Following the Core bootstrap instructions on a Kubernetes node failed at
  `failed to bind host port for 0.0.0.0:9091: address already in use`, because
  calico-node holds 9091 on every node, after two dozen containers had already
  started. Two entries also collided with each other
  (`MONITORING_SERVICE_HOST_PORT` and `PORTAINER_HTTPS_HOST_PORT` were both
  48091).

  All twelve are now pinned, Portainer moved to 49443, and
  `scripts/audit-host-ports.mjs` (strict in `make audit`) fails if a compose file
  publishes a port with no uncommented `env.example` entry, or if two entries
  claim the same host port.

- **The install instructions now match what the chart actually renders.**
  `INSTALL.md` told an evaluator to find the address with `kubectl -n vista get
  svc` — every Service in the namespace is ClusterIP, and the `IngressRoute`
  matches `Host(vista.local)`, so following it lands on a 404 at best. It also
  named `deploy/vista-vistaplatform-auth-service` for logs, where the
  Deployments are named plainly (`auth-service`), and credited the chart with
  installing Traefik's CRDs rather than requiring them. The chart's own
  `NOTES.txt` printed `job/<release>-vistaplatform-schema-migration`, a name
  that stopped existing when the Job gained a pod-template hash suffix; it now
  selects by label.

- **A verifier that starts before auth-service no longer waits five minutes for
  its keys.** The JWKS client fetched once at startup and then not again until
  the steady 300s interval, so a verifier that raced its issuer's startup — which
  is every service in a `helm upgrade` — ran with an *empty* key set until the
  first tick.

  Caught on the first real Core v0.1.0 deploy: every service logged
  `JWKS endpoint returned 404`, and platform-admin login was broken for exactly
  300 seconds, recovering on the dot. It looked benign only because legacy HS256
  still covered pre-existing sessions — with `jwtSigning.acceptLegacyHmac: false`
  it is a total auth outage on every restart.

  The first fetch now retries with exponential backoff (1s, 2s, 4s … capped at
  the interval) until it succeeds, then settles into the steady tick. Recovery
  is ~1s instead of 300s. Backoff rather than a tight loop so a genuinely absent
  issuer does not turn every verifier into a hot spinner against it.

  There is no bootstrap key set to fall back on, and that is not an oversight:
  Helm cannot derive a public key from the private PEM it generates, so fast
  retry is the fix rather than a workaround.

- **The public-tree publish no longer fails intermittently on self-hosted
  runners.** Self-hosted runners reuse `$RUNNER_TEMP` between jobs, and the
  exporter refuses to write into a non-empty directory — correctly, since it
  must never silently merge into a tree it did not create. The result was a
  publish that failed or succeeded depending on which of the six runners picked
  the job up.

  Seen for real: after the 2026-08-06 Actions outage the `core-v0.1.0` tag event
  was delivered late, landed on `actions-runner-4`, and died with
  `public-tree exists and is not empty. Refusing to overwrite` — while the
  dispatched run on a different runner had already published cleanly. Nothing
  was corrupted (it fails before pushing), but the next release would have hit
  it at random.

  The workflow now clears its own scratch directory first.

### Security

- **Session tokens are signed asymmetrically (ES256 + `kid` + JWKS); only two
  services can now mint one**.

  Every service signed *and* verified with one shared HS256 secret
  (`platform.jwtSecret`). That is a symmetric key held by ~17 pods: any one of
  them, or any log line or core dump that touched it, could forge a token for
  any user, any tenant, any role. There was no `kid`, so rotation was
  all-or-nothing — change the secret, log everybody out.

  Now one ECDSA P-256 private key is generated into a Secret and mounted **only**
  into the two token issuers, `auth-service` and `admin-service`. The other 15
  verify with the public half, polled from
  `/.well-known/jwks.json`. Chart render tests assert that split holds; a leak
  from a verifier grants nothing.

  New `shared/security/jwtkeys` handles keys, signing, verification, the JWKS
  document and its refresh. Key selection is by **algorithm class**, never by the
  `alg` the token asks for: an ES256 token resolves its `kid` against the trusted
  public keys, an HS256 token gets the legacy secret, and neither can reach the
  other's key material. That is pinned by a test that builds a real HS256 forgery
  from the published public key — mutation-verified to fail if the keyfunc ever
  regresses to handing back key bytes regardless of algorithm.

  **CSRF binding moved into the token.** The double-submit value was
  `HMAC(jti)` keyed by the shared JWT secret, which meant every *verifying*
  service needed that secret — so moving signing to asymmetric keys would have
  removed the shared secret from 15 services with one hand and kept it with the
  other. It is now a random `csrf` claim inside the signed token: unforgeable
  without forging the token, and needing no shared secret at all. Pre-cutover
  sessions fall back to the old derivation until they expire.

  **Rollout is staged and non-breaking.** Sessions minted before the upgrade keep
  verifying for their full lifetime; nobody is logged out. `JWT_SECRET` is still
  injected everywhere while `jwtSigning.acceptLegacyHmac` is true (the default).
  Setting it to `false` one refresh-token lifetime later is the step that
  actually retires the secret — after that upgrade it reaches only the two
  issuers and an HS256 token is rejected outright. Until then this change has
  reduced the number of pods holding a forgery key from ~17 to 2, not to 0.
  Runbook, including key rotation and revocation: deployment-guide **§5H**.

  Also: platform-admin login moved from the general API rate limit to the auth
  one, and the JWKS endpoint is published at the edge so an external verifier can
  validate our tokens without being handed a secret.

  `jwtSigning.enabled: false` restores the previous behaviour exactly, verified
  by a render test — the rollback is real, not nominal.

- **Service-to-service `/internal/*` routes are no longer published on the
  public ingress**.

  Two HMAC-gated S2S endpoints rode the per-service `PathPrefix` catch-all onto
  the internet: `notification-service/internal/send` — the raw delivery path
  that deliberately bypasses the rule engine — and
  `sensor-manager/internal/pcap/jobs/:id/results`. Both are now denied at the
  edge on **every** host (unlike the admin plane there is no host they belong
  on), declared in `admin_plane.internal_prefixes` in the service registry and
  generated by `make generate-k8s-ingress`.

  This is defence in depth, not a live hole: they were already gated by
  `INTERNAL_AUTH_SECRET`. The argument for doing it anyway is that no browser
  and no customer integration ever calls them, so publishing them at the edge
  bought nothing while exposing an HMAC verifier and its parsing to anonymous
  internet traffic — with a single shared secret across every service and no
  rotation lever as the only line of defence.

  Every caller was verified to be an in-cluster Go service reaching its peer
  through `PeerURL`; S2S traffic addresses Services directly and never transits
  Traefik, so this does not affect it. `scripts/audit-admin-plane.mjs` now fails
  when a service mounts an HMAC-gated group whose path is undeclared, or when a
  declared prefix stops generating its deny — both mutation-tested, along with
  neutering the deny middleware to a routable CIDR.

- **Integration and connector credentials are encrypted at rest in the six
  stores that still held them in plaintext, and there is now one blessed way to
  do it**.

  The plaintext stores were `tenant_notification_channels.config` and
  `platform_notification_channels.config` (Slack webhook URLs, PagerDuty
  integration keys, webhook auth headers), `monitoring_notification_channels.config`,
  `discovery_alert_configs.slack_webhook_url` (a Slack incoming-webhook URL is
  a full posting credential), `security_incident_webhooks.secret` (an HMAC
  signing key — encrypted, deliberately not hashed, because the receiver needs
  the same bytes to verify), and `integrations.auth_config` as written by
  inventory-service.

  The cause was procedural rather than careless: there was no shared "encrypt
  these fields" helper, so eight services each hand-rolled an
  `encryptConfig`/`decryptConfig` with a private, drifting denylist — three of
  them disagreed about whether `access_key_id` was a secret — and a new
  connector's author had nothing to reach for, making `json.Marshal(config)`
  the path of least resistance. The strategic fix is
  **`shared/security/credentials`**: a `Cipher` + declarative `Policy` over
  `shared/security/encryption`, owning the `enc:v1:` ciphertext tag and the
  plaintext-migration semantics in one place. Existing plaintext rows keep
  reading correctly and are encrypted on their next save; a tagged value that
  will not decrypt is an error rather than a credential made of ciphertext.

  `integrations.auth_config` was the sharpest case: **two services in different
  modules write that column**, and they disagreed — inventory-service stored
  plaintext while admin-service's MSP writer stored untagged ciphertext under a
  narrower denylist, so a tenant's credentials were protected or not depending
  purely on which endpoint they hit, and neither service could read the other's
  rows. Both now share `credentials.IntegrationAuthConfigPolicy`, and the
  read path recovers all three provenances (plaintext, untagged ciphertext,
  tagged ciphertext).

  `ENCRYPTION_MASTER_KEY` is now declared for audit-service (registry
  `required_secrets`, all three compose files in the strict `${VAR:?}` form,
  chart `secrets.encryptionMasterKey`) so the latent SIEM-credential store
  cannot land plaintext, and the production dev-default guard
  (`RejectInsecureDefaults`) now covers the key in monitoring-service,
  cluster-sensor-service and audit-service.

  A new `make audit` check, `scripts/audit-credential-encryption.mjs`, fails
  the build when a Go file writes a credential-shaped column without importing
  the helper — because fixing six instances without fixing the procedure just
  resets the clock. Every store is covered by `TestIntegration_*` tests that
  assert on the **raw column bytes**, not merely the round trip: an "encrypt"
  that returns its input passes a round-trip test perfectly.


- **The cross-tenant platform-admin API is no longer served on the public tenant
  host, and the admin plane can be restricted to named source networks**.

  Before this, a separate `tls.adminDnsName` was only a second hostname on the
  same Traefik, same entrypoints, same load balancer. The platform-admin API —
  every `/admin-service/admin/**` route plus the cross-tenant `/admin`,
  `/platform`, `logs`, `alerting` and `gateway` groups in nine other services —
  was reachable from the public internet on the *tenant* host, gated only by its
  platform-admin role check. Verified on the development cluster:
  `https://<tenant-host>/api/v1/admin-service/admin/auth/me` answered `401`,
  i.e. the request reached admin-service. "We don't publish the admin URL" is
  obscurity, and obscurity is not an access control an auditor accepts.

  Two independent controls, both driven from `admin_plane:` in
  `standards/service-registry.yaml` (18 declared prefixes, one declared public
  exception) and rendered by `make generate-k8s-ingress`:

  - `adminPlane.restrictToAdminHost` (**default true**, active whenever
    `tls.adminDnsName` is set) serves the platform-admin API on the admin host
    only and returns `404` for it on the tenant host. Skipped on a single-host
    install, where there would be nowhere else to serve the console from.
  - `adminPlane.ipAllowList` (**default off**) restricts the admin plane to
    operator CIDRs via a Traefik `IPAllowList`, with `ipStrategy` for
    deployments behind a load balancer. Off by default because the chart cannot
    guess a customer's network and a wrong guess locks them out; `helm install`
    now prints a warning describing the exposure while it is off.

  The inbound billing-provider webhook stays on the public host as a declared,
  justified exception — the provider posts from its own infrastructure and
  authenticates by signature, not by network position.

  Verified end to end against the development cluster: all 70 admin-plane
  paths return `404` on
  the tenant host and reach their service on the admin host, with the
  tenant-facing surface (including the *tenant*-admin routes that share
  `/sensor-manager/admin/`) unchanged.

  Three guards keep it from rotting, each mutation-tested in both directions:
  `scripts/audit-admin-plane.mjs` (in `make audit`) fails when a Go service
  mounts a platform-admin-gated group whose path is undeclared, or when a
  declared prefix stops generating its deny/allow pair; and two real-router
  tests in admin-service require every one of its 69 (Core) / 184 (Enterprise)
  mounted routes to be either declared admin-plane or on an explicit,
  justified public allow-list.

  Found while building this: `/compliance-engine/admin/**` (per-tenant
  re-evaluation, platform alert feed) was cross-tenant and undeclared — the
  source scanner caught it, a hand-written list had missed it. Also fixed a
  matching gap the generated YAML looked correct for and only live testing
  exposed: Traefik's `PathPrefix(/x/y/)` does not match `/x/y`, so groups with a
  handler on the group root (`/monitoring-service/logs`) escaped the deny.

  Known gap, deliberately recorded rather than papered over: `POST`/`PUT` on
  `/inventory-service/algorithms` are platform-permission-gated *methods* on a
  path whose `GET` is tenant-facing. Host-based splitting cannot express that;
  the RBAC gate remains the only control there.

  Platform-admin login (`/admin-service/auth/`) also moves from the general API
  rate limit (1000/s) to the auth limit (200/s), matching how tenant login is
  treated.

  Operators: see deployment-guide **§5G**. Enabling the IP allow-list must be
  verified from an address *outside* `sourceRange` — with a wrong
  `ipStrategy.depth` the list matches the load balancer's own address and admits
  everyone while looking like it works.


- **`tools/qa-platform/ui` moved to `react-router-dom@^7.18.2`** (from
  `^6.28.0`, lockfile was at 6.30.3), clearing the three open-redirect
  advisories that cover **every** 6.x — `GHSA-jjmj-jmhj-qwj2`, the
  `<Link>`/`useNavigate` backslash bypass of CVE-2025-68470, and the
  `deserializeErrors()` constructor injection. 6.30.4 is the last 6.x that
  exists, so there was no patched 6.x; v7 was the only remedy. This was the
  last tree in the repo still on 6.x.

  **package.json + lockfile only — no source change.** All 5 `react-router`
  import sites use the declarative API only (`BrowserRouter`, `Routes`,
  `Route`, `Navigate`, `NavLink`, `Link`, `useNavigate`, `useParams`); there
  is no data router, no `json()`/`redirect()`/`defer()`, and **no splat route
  anywhere**, so `v7_relativeSplatPath` cannot apply. Every navigation target
  is a literal leading-slash path or a template literal with a leading slash.

  Verified in a **real headless browser** against both `vite dev` and the
  production `vite preview` build (28 assertions each, both green): the
  `useNavigate()` push, `<NavLink>` active styling / `aria-current`,
  `<Navigate replace>` redirects and `useParams` resolution are runtime-proven
  rather than statically resolved.

  **Note:** this leaves qa-platform on `react-router-dom`, which is EOL at
  7.18.2, and therefore carrying `GHSA-qwww-vcr4-c8h2` (RSC-mode CSRF,
  `>=7.12.0 <8.3.0`) — unreachable in a client-only SPA with no RSC, loaders
  or actions. The two consoles cleared that advisory by going to React 19 +
  react-router 8 (below); qa-platform is still on React 18.3.1 and was
  deliberately not taken across a React major in this change. It has its own
  lockfile outside the npm workspace, so root `npm audit` does not see it.

- **Both UIs moved to React 19 + React Router 8** (`react@^19.2.8`,
  `react-dom@^19.2.8`, `react-router@^8.3.0`), closing
  **GHSA-qwww-vcr4-c8h2** (RSC-mode CSRF, HIGH), which affects
  `>=7.12.0 <8.3.0` and is fixed only in 8.3.0. `npm audit --omit=dev` now
  reports nothing for react-router.

  The two upgrades are one change, not two: react-router 8.3.0 declares
  `react: >=19.2.7`, so there is no route to the patched router that does not
  also cross the React major.

  `react-router-dom` **does not exist at 8.x** (7.18.2 is its last release) —
  it was only ever a thin re-export. The v7 upgrade deliberately kept importing
  from it to hold the diff small; that debt comes due here, so imports were
  renamed to `react-router` across 53 files. That rename is the bulk of the
  diff and is mechanical — one import specifier per file, no other source
  change in either console.

  React 19 itself required no code changes. The removed APIs were audited by
  grep rather than assumed: neither console uses `defaultProps` or `propTypes`
  on function components, string refs, legacy context, `ReactDOM.render`,
  `unmountComponentAtNode`, `findDOMNode`, or `react-dom/test-utils`. Both
  already mount via `createRoot` under `StrictMode`.

  Peer deps: `@stripe/react-stripe-js@6.8.0` (already on main from the Stripe
  browser-SDK upgrade) peers `react >=16.8.0 <20.0.0`, so it installs cleanly
  against React 19 with a single deduped copy — no root `overrides` required.
  `@tanstack/react-query`, `lucide-react`, and `react-hot-toast` already allowed 19.

  Note `react-router@8` raises the Node floor from `>=20` to `>=22.22.0`. CI
  and the UI Dockerfiles already build on Node 24.

  The routing-contract tests added with the v7 upgrade were kept and now run
  against react-router 8's real matcher; the version-floor assertions in them
  were rewritten to read `react-router` (asserting `react-router-dom` is gone)
  and to pin React at the `>=19.2.7` floor the router requires.

- **Both UIs moved from React Router v6 to v7** (`react-router-dom@^7.18.2`),
  closing the open-redirect → XSS advisories that affect every 6.x release
  (GHSA-jjmj-jmhj-qwj2; the `<Link>` / `useNavigate` backslash bypass of
  CVE-2025-68470; the `deserializeErrors()` constructor injection). This is not
  a patch bump — the advisories cover `>=6.0.0 <7.18.0` and 6.30.4 is the last
  6.x that exists, so v7 is the only remedy.

  No application source changed. Both consoles use only the declarative router
  API and pass literal internal paths to every `to=` / `navigate()`, so none of
  v7's now-default future flags (`v7_relativeSplatPath`, `v7_startTransition`,
  and the data-router-only ones) altered behaviour. Routing-contract tests were
  added to `frontend-v2` and `admin-ui-v2` to demonstrate that rather than
  assume it — they read the real route tables out of `App()` and resolve real
  URLs through react-router itself.

  Known residual at the time: 7.x reports GHSA-qwww-vcr4-c8h2 (RSC-mode CSRF),
  fixed only in react-router 8.3.0, which requires React >= 19.2.7. It was not
  believed exploitable here — the advisory is limited to the unstable RSC APIs
  and both consoles are client-only SPAs with no server runtime, loaders,
  actions or RSC — but it left an open HIGH in `npm audit`. **Superseded by the
  React 19 + React Router 8 entry above, which closes it.**

### Changed

- **The public CHANGELOG now carries the version actually being released.**
  `prepare-public-tree.sh` wrote a hard-coded `## [0.1.0]` section into the
  exported tree, which was right for exactly one release: the second Core
  release would have published a changelog announcing 0.1.0 while the tag, the
  chart and all 19 images said 0.2.0 — a public artifact contradicting itself in
  the one file a reader opens to find out what changed.

  The export now takes `PUBLIC_VERSION` (bare, no leading `v`) and
  `publish-public-tree.yml` passes it. With it unset — a local rehearsal, not a
  release — no versioned section is written at all, so a forgotten value shows
  up as a missing heading rather than a stale one. The regression test asserted
  the hard-coded string, so it encoded the bug; it now asserts the opposite.

- **Core and commercial releases now use separate tag namespaces**: Core ships
  on `core-vX.Y.Z`, the commercial line keeps a bare `vX.Y.Z`, and neither
  fires the other's workflow.

  One `v*.*.*` tag used to drive all three release workflows. That worked only
  while both editions shipped in lock-step — the moment a Core-only tag was cut,
  `release-customer` tried to promote Harbor images that did not exist for it
  and failed. All four `v0.0.x-test` publish rehearsals left a red run behind
  them. The version lines had diverged too (commercial at v3.6.0, Core starting
  at v0.1.0), so a Core tag read as a regression of the commercial product.

  Note the asymmetry: the tag pushed to the **public** repo is the stripped
  `vX.Y.Z`, because over there the repository *is* Core and a prefix would be
  noise. `release-core.yml` therefore triggers on `v*.*.*`; in the private repo
  it matches the commercial tags too and no-ops, because its guard job skips any
  tree containing `services/*/ee`.

  That guard is now load-bearing, so `scripts/test-release-tag-split.mjs` (in
  `make standards-check`) fails if it is removed, if the namespaces overlap
  again, or if the prefix strip is dropped. It asserts the glob semantics
  against a real ref-glob matcher rather than assuming `v*.*.*` is anchored.
  Runbook: RELEASE_PROCESS.md "Releasing Core".

- **TypeScript 5.9 → 6.0.3 across all five workspaces**, and unified: `api/` was
  on `^5.6.0` and `packages/primitives` on `^5.4.0`, so three different
  compilers were type-checking code that shares types.

  **Not 7**, deliberately. TypeScript 7 is the native Go port and does not
  expose the JS compiler API; `openapi-typescript` calls `ts.factory` directly
  and dies with `Cannot read properties of undefined (reading
  'createKeywordTypeNode')`. That generator produces
  `api/clients/typescript/` and is wired into `make api-contract`, so on 7 the
  contract pipeline cannot regenerate the client — taking drift detection and
  the Go contract tests with it. Our own source is already TS 7-clean (verified
  by installing 7 and type-checking: 0 errors once the `vite-env.d.ts` gap
  below was closed); only the build-time dependency blocks it. Tracked in.

  Known peer mismatch: `openapi-typescript@7.13.0` peers `typescript@^5.x`, so
  `npm ls` reports TS 6 as `invalid`. Generation works and `npm ci` succeeds;
  it resolves when upstream supports 6.


- **Stripe browser SDKs upgraded to current majors** in `frontend-v2`:
  `@stripe/stripe-js` `^2.4.0` → `^9.13.0` (7 majors) and
  `@stripe/react-stripe-js` `^2.4.0` → `^6.8.0` (4 majors). Server-side Stripe
  (`services/admin-service/ee/billing*`, stripe-go) is untouched.

  The material change is invisible to the compiler: `@stripe/stripe-js` majors
  track Stripe's flora-named API release trains, so `loadStripe()` now fetches
  `https://js.stripe.com/dahlia/stripe.js` instead of `https://js.stripe.com/v3`.
  Every method the checkout flow calls survives that move — Dahlia removed
  `handleCardPayment`, `confirmPaymentIntent`, `handleFpxPayment`,
  `handleCardSetup`, `confirmSetupIntent`, `createSource` and `retrieveSource`,
  none of which this code uses; `confirmSetup` and `confirmCardPayment` are the
  documented replacements and remain. The two React-side breaking changes
  (v4's `/checkout` entry-point split, v5's `CheckoutProvider` reshape) apply
  only to the Checkout Sessions API, which this codebase does not use.

  `StripeElementsOptions` became a `clientSecret | mode` discriminated union in
  stripe-js v8. The checkout Elements options were extracted to
  `checkoutElementsOptions()` and pinned by tests, because the `mode` arm
  type-checks identically while confirming nothing against our SetupIntent —
  a card collected and never charged.

  **Not verified:** no live or test Stripe key exists in this environment, so
  no SetupIntent was created, no PaymentElement mounted, and no 3DS/SCA
  confirmation exercised. See the PR for the list.

- **Regulated compliance frameworks now ship as a signed Enterprise content
  bundle** instead of being seeded into every install. SOC 2 Type 2, PCI-DSS
  4.0, ISO/IEC 27001:2022, NIST CSF 1.1 and IEC 62351-3 moved out of
  `scripts/database/seed.sql` into
  `services/compliance-engine/ee/content/frameworks-regulated.sql`, applied by
  the chart's seed-data Job when `enterprise.contentBundle.enabled=true`
  (default `false`). The bundle carries a detached ECDSA P-256 signature — the
  same key that verifies entitlement tokens — which an init container verifies
  with `openssl` before any SQL runs; a missing, empty, or invalid signature
  fails the Job, and an unsigned bundle fails the release workflow. Chosen over
  a hosted feed because it is revocable by non-renewal, versioned with the
  release, works air-gapped, and needs no service to operate.

  The six **free** frameworks (`best-practices`, `pqc-readiness`,
  `cert-hygiene`, and the three `cert-expiry-*`) stay in the Core seed. A Core
  install now seeds 6 frameworks; an Enterprise install with the bundle enabled
  has 11.

  **No action for existing Enterprise deployments.** The bundle upserts by
  `(code, version)` and by control id, so re-applying is a no-op beyond
  `updated_at` — framework row ids are preserved, so tenant licenses, findings
  and score rollups keep resolving. Not applying it deletes nothing.

  **Action for the next release:** the bundle must be signed before tagging
  (`make sign-content-bundle EDITION_SIGNING_KEY=<path>`, commit the `.sig`) or
  the release workflow's staging gate fails by design rather than shipping a
  chart whose Enterprise installs would silently seed no regulated frameworks.

### Fixed

- **`packages/primitives` now declares the React types it compiles against**,
  fixing the `Frontend - admin-ui-v2` typecheck failure that left on
  `main`.

  The package has `.tsx` files that `import React from 'react'` and is consumed
  as **source** (`"main": "./src/index.ts"`), so a consuming UI's `tsc` compiles
  them — but it declared `react` only as a peer dependency and `@types/react`
  nowhere. It resolved React's types purely by them being hoisted up from one of
  the two UIs, which is not something a package may rely on: npm's placement
  depends on install state, and on a clean `npm ci` before this change
  `@types/react` landed **only** in `frontend-v2/node_modules` and
  `admin-ui-v2/node_modules` — unreachable from `packages/primitives`. With the
  declaration it hoists to the root, reachable from anywhere.

  Honest caveat: the CI failure does **not** reproduce locally, before or after,
  with the runner's exact commands on a clean install. This fix is correct on its
  own merits and removes the resolution dependency the failure is consistent
  with, but CI is the thing that gets to confirm it.


- **Platform-admin refresh rejected every ES256 session minted after.**
  `admin-service` signed refresh tokens with the new `platformSigner` (ES256)
  but `RefreshToken` still verified with an HMAC-only keyfunc, so login
  succeeded and the first refresh always 401'd. Verification now uses the same
  `jwtkeys.Verifier` path as minting (public keys from the signer + legacy
  `JWT_SECRET` during the migration window). Pinned by
  `TestParsePlatformRefreshToken_AcceptsES256WhenSigning`.

- **Three database read/write paths that could never have worked against
  Postgres**, all found while adding the integration tests and all the same
  root cause — a `map[string]interface{}` struct field bound to a `jsonb`
  column, which `database/sql` cannot convert in either direction:

  - `inventory-service` `ListIntegrations` failed on every call
    (`integrations.auth_config`), so the tenant self-service integrations list
    was dead.
  - `cluster-sensor-service` `GetAlertConfigs` failed on every call
    (`discovery_alert_configs.conditions`), and `UpdateAlertConfig` failed on
    every call including with a nil map.
  - `GetAlertConfigs` additionally failed on any row with a NULL
    `slack_channel`/`slack_webhook_url` — which includes the three defaults
    auth-service seeds at tenant creation.

  Fixed with a shared `database.JSONMap` (a `sql.Scanner`/`driver.Valuer` map
  that JSON-encodes identically, so no API response shape changes) plus
  `COALESCE` on the two nullable text columns.


- **Four compliance-evaluation correctness defects, each of which looked like
  working code while doing nothing**. All four were reproduced with a
  failing test before being fixed; the new coverage is four `TestIntegration_*`
  groups plus pure-logic tests for the scoring model.

  - **A CBOM compliance attestation signed evidence claiming `finding_count: 0`
    for tenants that had findings.** `AttestationBuilder.Build` queried
    `compliance_findings` on a bare pooled connection, so with RLS enforced
    `app.tenant_id` was unset and every row was invisible. The query was
    correct; the connection was not. `Build` now takes the tenant explicitly and
    reads inside a tenant-scoped transaction, with a `tenant_id` predicate as the
    primary control. The persister also logs when an attestation is skipped —
    absent-because-it-failed and absent-because-clean previously looked
    identical on the artifact.

  - **The premium `threshold_overrides` feature had no effect.** The Enterprise
    authoring surface checked entitlement, checked the framework licence, and
    wrote `tenant_measurement_overrides` rows that the rule evaluator never read.
    `getControlMeasurements` now folds the tenant's override (predicate and
    severity) onto the platform measurement. An override whose predicate does not
    decode to a non-empty object is ignored rather than applied: every rule
    branch returns "passed" when it cannot read its predicate, so honouring an
    empty one would silently disable the control while still reporting it
    evaluated.

  - **`EvaluateMultipleFrameworks` reported 0 passing / 0 failing controls
    always.** It compared `StatusEffective` — always `PASS`/`WARN`/`FAIL` —
    against lowercase literals, so the switch matched nothing. Statuses are now
    shared constants rather than repeated string literals, which is what let the
    casing drift in the first place.

  - **Two divergent framework-score models.** The materialized rollup
    (`tenant_framework_scores`) and the `/frameworks/context` scorecard scored by
    flat control count while the live evaluation scored severity-weighted, so the
    same tenant+framework showed different numbers depending on which page you
    were on (20 vs 50 on the regression fixture). Severity-weighted is the
    documented model, so there is now one `frameworkScore` primitive and the flat
    paths delegate to it. The rollup also now derives control status from the
    worst **non-suppressed** ACTIVE finding, matching the live path — an
    explicitly accepted risk no longer drags the materialized score down.

- **The tenant console offered Settings → Account → Billing on a Core
  deployment, where every one of its calls 404s**. `/my-billing/**` is
  served by `services/admin-service/ee/billingapi`, which the Core export
  strips, so the page rendered "Couldn't load the subscription" and "Couldn't
  load invoices" — broken software rather than "this is a paid feature". The
  `billing.read` permission cannot separate the two: a Core tenant admin holds
  it perfectly legitimately.

  Billing is now gated on a new **`billing_portal`** entitlement key, registered
  on all four surfaces (`shared/entitlements` `editionByItem`, auth-service
  `knownFeatures`, the closed OpenAPI `FeatureFlags` shape + generated client,
  and the `FeatureName` union / `defaultFeatures` map), plus a `billable_items`
  catalog row so it appears in admin → Plans → Entitlements. Off ⇒ the rail
  entry is hidden, a deep link to `/settings/billing` renders an upgrade card,
  and the two queries never fire. Settings → **Usage & Limits** is deliberately
  *not* gated — it reads auth-service `/billing/usage/current`, which is Core.

  A repo-wide sweep of every tenant nav entry, route and chrome component
  against the actual Core route set (produced by running the export) found this
  to be the only ungated paid surface: SSO, Custom Policies, CMDB/ITSM sync,
  SIEM export, CBOM signing/compare and white-label branding were all already
  gated, and no primary-nav section (Dashboard, Discovery, Inventory,
  Risk & Compliance, Remediation) or global chrome component calls an `ee/`
  route. Registration parity is now pinned by tests on both sides
  (`features_registration_test.go`, `feature-registration.test.ts`) so a
  half-wired flag fails a build instead of silently disabling a gate.

- **The `custom_branding` flag had an empty description in the auth-service
  OpenAPI spec**, and its text had been swallowed into `siem_export`'s — a YAML
  block-scalar continuation introduced when those two keys were inserted between
  them. Cosmetic, but it shipped in the generated TypeScript client.

- **Scheduled interrogations never fired.** `SchedulerService.ProcessDueSchedules`
  had zero callers anywhere in the repo — no ticker, goroutine or cron. Tenants
  could create cron schedules in the UI and nothing ever swept for due rows, so
  `next_run_at` simply drifted into the past. A `SchedulerWorker` now drives the
  sweep on an interval (`INTERROGATION_SCHEDULER_INTERVAL`, default 1m;
  kill-switch `INTERROGATION_SCHEDULER_ENABLED`), started from
  device-interrogation-service's `main`. The sweep itself was rewritten to claim
  due rows inside one transaction: the original issued
  `SELECT … FOR UPDATE SKIP LOCKED` through `QueryContext`, whose implicit
  transaction ends with the statement, and advanced `next_run_at` only on a
  *successful* trigger — so once a loop existed, two replicas could double-fire
  the same schedule and any failing trigger would be retried on every tick
  forever.

- **The device agent never sent a heartbeat.** `OutboundClient.SendHeartbeat`
  existed but had zero callers, so `device_agents.last_heartbeat` never moved
  after registration. The agent showed as never-seen in the platform's liveness
  view, and — because the `discovery_agent_offline` detector skips rows whose
  `last_heartbeat` is NULL — a genuinely dead tenant agent raised no alert at
  all. The agent now beats on start and every `HEARTBEAT_INTERVAL` (default 60s,
  well inside the detector's 15-minute dwell). Separately, the *in-cluster*
  platform agent had the opposite problem: auto-registration stamped
  `last_heartbeat` once at boot and nothing refreshed it, and that detector — unlike
  `sensor_offline` — does not exclude platform-owned rows, so a healthy service
  opened a false high-severity alert 15 minutes after every restart.
  `PlatformAgentHeartbeat` now keeps that row fresh.

- **Remote device interrogation always failed on credentials.** The platform and
  the device agent disagreed about the job credential payload three ways at
  once. The agent expected `{"encrypted_data": …}`; the embedded-credential path
  sent the device password taken from `GetDevice`, which *masks* it for API
  responses — so what reached the agent was `abcd****wxyz`, a twelve-character
  fragment of a ciphertext; the legacy `credential_id` path sent
  `{"_job_key", "config": {…}}` with the real fields nested a level below where
  the agent looked, so it ran with no credentials. There is now one canonical
  shape, defined and implemented once in `shared/agentcreds` and linked by both
  sides, sealed per-job for the specific claiming agent (key =
  SHA-256(job id ‖ 0x00 ‖ that agent's registration key)). Two-sided contract
  tests, anchored on a frozen vector, fail on either side if the wire shape,
  derivation or encoding drifts. Bulk interrogation also silently ignored
  embedded device credentials entirely; it now uses the same path.

- **Monitoring alerts were never persisted, so they re-fired every cycle.** The
  alert evaluator built an `AlertHistory`, logged it and discarded it — the code
  said so: *"Save alert to database (this would need to be added to
  AlertingService) / For now, log it"*. Its own de-duplication guard therefore
  queried an always-empty table and could never suppress anything, so one
  breached threshold re-notified every ~5 minutes indefinitely and never
  resolved. `AlertingService` gained the missing persistence
  (`RecordAlert` / `GetActiveAlertForThreshold` / `ResolveAlertsForThreshold`);
  the evaluator now fires once per breach, closes the alert when the metric
  recovers, and re-opens exactly once on a severity escalation. The de-dup key
  moved from "newest active alert for this service, compared by name" to the
  threshold id, so one busy threshold can no longer mask another on the same
  service. No schema change — `monitoring_alert_history` already had the
  columns.

- **The PR gate's "Lint (eslint)" step ran no linter**. In both UIs the
  `lint` script was `tsc --noEmit`, neither UI had eslint installed, and the
  step duplicated the preceding `npx tsc --noEmit`. Every frontend PR reported a
  passing lint gate that linted nothing. Now:

  - eslint 10 + `typescript-eslint` 8 + `eslint-plugin-react-hooks` 7 are
    declared once in the root `devDependencies`, with a shared flat config at
    `eslint.config.base.mjs` that each UI's `eslint.config.js` imports —
    matching how the root already shares `typescript`/`react` (ADR-0005).
  - `lint` is `eslint .`; the typecheck moved to its own `typecheck` script, so
    neither step claims to do the other's job.
  - Enforced at **error** (zero findings): `react-hooks/rules-of-hooks`,
    `react-hooks/exhaustive-deps`, `@typescript-eslint/no-unused-vars`,
    `no-unused-expressions`, `require-await`. Each was mutation-tested — a
    deliberate violation fails the gate, removing it makes it pass again.
  - The first-run backlog (639 frontend-v2 / 310 admin-ui-v2 findings,
    dominated by `no-unnecessary-type-assertion`, `prefer-nullish-coalescing`
    and `no-floating-promises`) is reported as **warnings**, never disabled,
    with per-rule counts recorded inline in the config. Each app's `lint`
    script pins `--max-warnings` at its current count, so the backlog can
    shrink but never grow. Burn-down tracked in.
  - Fixed while wiring it up: 15 `exhaustive-deps` violations across 9 files
    (`const all = data ?? []` producing a fresh array identity every render, so
    the `useMemo` blocks below it never hit), 4 ternaries used as statements,
    and a stale `eslint-disable` directive.
  - `make lint` now runs eslint on **both** UIs (it ran `npm run lint` in
    `frontend-v2` only — which was the same no-op `tsc`); `CLAUDE.md` and
    `AGENTS.md` no longer claim it runs flake8, which it never did.

- **Nightly `test-backend` had been red every night for a month**. Two
  packages asserted a pre-open-core entitlement matrix that `seed.sql`'s
  edition-gate correction had deliberately invalidated: no subscription tier may
  grant an edition-gated capability, so `pro.ot_active_probing` is now seeded
  `false` and the per-tier catalogue grew from 16 items to 18 (`cmdb_sync`,
  `siem_export`). `shared/entitlements` and `admin-service`'s entitlement tests
  were pinning the old values.

  - The two resolver tests that needed a tier-granted `true` boolean now create
    a throwaway tier instead of reading one off the seed — no seeded tier grants
    any boolean any more, so they were testing the seed, not the resolver.
  - Added `TestResolve_EditionGatedCapabilitiesNeverGrantedByTier`, which walks
    every seeded tier × every edition-gated key and pins the invariant directly.
    Mutation-tested: removing `ot_active_probing` from seed.sql's corrective
    UPDATE makes it fail.
  - `admin-service`'s count assertion now compares against the billable-item
    catalogue rather than a hard-coded 16, so adding a catalogue item no longer
    breaks the nightly silently.
  - `make test-integration-db` never ran either package — its `-run Integration`
    filter does not match `TestResolve_*` / `TestGetTierEntitlements_*`, which is
    why this survived a month of red nightlies without anyone reproducing it
    locally. Both are now in the script.

  The `security-scan` half of was **not** our code: in the cited run it
  failed only at `Upload scan artifacts` (artifact-service infrastructure), and
  in the 2026-07-29 run at a govulncheck CVE since resolved. It has been green
  since.

- **The nightly's npm-audit gate audited nothing** — same shape as, found
  while fixing it. Both the hard gate and the dev-deps info step looped over
  `web-ui/` and `admin-ui/`, the v1 UIs deleted in, behind an
  `if [ -f "$app/package-lock.json" ]` guard; the loop body had not executed
  since that deletion while the step summary printed "✅ Clean". Both now audit
  the workspace-root lockfile (which is the only one — `api/`, `packages/*`,
  `frontend-v2` and `admin-ui-v2` are npm workspaces), and a missing root
  lockfile now fails the gate rather than skipping it. The nightly's frontend
  job also gained the lint and typecheck steps its own header already claimed
  it ran.


- **React was installed twice.** The lockfile hoisted `react@18.3.1` to the root
  while nesting `react@19.2.8` under each UI, because `packages/primitives`
  declares `peerDependencies: react >=18` and npm satisfied it with an old
  pinned copy rather than deduping. Since primitives is consumed as *source* by
  both consoles, it resolved the root React 18 — producing `TS7016` on a clean
  `npm ci`, and two React copies in one bundle at runtime (the classic
  `Invalid hook call`). Root now declares `react`/`react-dom` at `^19.2.8`, and
  the tree dedupes to a single 19.2.8. The primitives peer range is unchanged
  and still correct — it does support both.

- **`tsc -b` from the repo root has been broken since the v1 UI cutover.** The
  root `tsconfig.json` referenced `./admin-ui`, which moved to `_legacy/` in
  and was deleted in, so the solution build failed with `TS5083`.
  Nobody noticed because each workspace is normally checked individually. It now
  references the four workspaces that exist.

- **`admin-ui-v2` had no `src/vite-env.d.ts`**, so `import './index.css'` had no
  type declaration — an asymmetry with `frontend-v2`, which has always had one.
  Harmless under TS 5/6, an error under TS 7.

## [0.1.2] - 2026-08-07

### Fixed

- **`release-core.yml` could publish a release with zero binaries and an empty
  `SHA256SUMS`**. The download step for the sensor/device-agent build
  artifacts had no `pattern` filter, so `actions/download-artifact` pulled down
  every artifact the run produced — including per-image build provenance — and
  a naming mismatch made the step fail outright rather than stage anything. It
  now downloads only the `bin-*` artifacts and asserts at least 7 arrived
  before continuing, so a broken artifact name fails loudly instead of shipping
  a binary-less release.

## [0.1.1] - 2026-08-07

### Added

- **Documentation reorganized into Core/Enterprise/MSP edition layers**, with
  the published edition matrix generated from the same code that gates
  entitlements (`shared/entitlements/editions.go`) rather than hand-maintained,
  so it cannot drift from what the product actually gates.
- **Every Core release now publishes pre-built sensor and device-agent
  binaries** for Linux, Windows and macOS, signed and attached to the GitHub
  Release alongside a signed `SHA256SUMS`.

### Fixed

- **The quickstart's `INFLUXDB_PASSWORD` had silently never rotated** — a
  published placeholder value shipped readable in the repository.
  `bootstrap-env.sh` now rotates it like every other generated secret.
- **A captured lab sensor configuration — a real enrollment credential, sensor
  UUID, and an internal control-plane URL — had been shipping in
  customer-facing documentation.** The export now gates on lab identity and
  registration-key patterns directly rather than relying on the scrub alone.
- **The first JWKS fetch on a cold start could stall for a full poll interval**
  before the first retry; it now retries immediately.
- Teardown scripts now scope to the compose project instead of matching
  containers/networks by name, and every published host port is pinned in
  `env.example` to avoid silent collisions with the host.

## [0.1.0] - 2026-08-06

### Added

- **Initial public release of VistaPlatform Core** — the open-source edition
  of the platform, carved out of the commercial codebase: discovery (sensor,
  device-interrogation agent, cloud connectors), CMDB-aligned inventory,
  cryptographic and post-quantum assessment, the compliance engine with six
  free frameworks, CBOM generation with CycloneDX export, and the full
  security baseline (tenant isolation, service-mesh mTLS, RBAC, audit
  logging) — nothing security-relevant held back. Published under
  [FSL-1.1-ALv2](LICENSE.md); every image and the chart are built from this
  source, unobfuscated, and cosign-signed.
