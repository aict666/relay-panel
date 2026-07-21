# Changelog

All notable changes to RelayPanel are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

Node-only changes are in **CHANGELOG-NODE.md** (panel and node release on
independent `v*` / `node-v*` tracks since this release).

---

## [Unreleased]

## [1.3.6] - 2026-07-21

### Security

- **Authentication and authorization now fail closed.** Login, current-user
  resolution, group access, node identity validation, and administrative
  mutations no longer acknowledge success when persistence or verification
  fails.
- **Generated node install commands are shell-safe.** Tokens and panel URLs are
  quoted as data, preventing shell metacharacters from changing the command.

### Changed

- **Administrative writes use transactional compare-and-set semantics.** Plans,
  users, rules, tunnels, profiles, groups, settings, and purchases reject stale
  forms instead of overwriting concurrent changes or charging against a changed
  catalog.
- **Rule creation accepts connection and restart limits directly.** The create
  path now validates the same bounds as updates, eliminating the follow-up edit
  window.

### Fixed

- **Traffic limits retain their exact byte value.** Opening and saving a form no
  longer rounds an unchanged quota through a two-decimal GiB display, and unsafe
  browser-sized values are rejected.
- **Node status is durable and key-safe.** Invalid node identifiers are rejected,
  storage and lease-renewal failures are surfaced, and GeoIP cleanup preserves
  addresses still reported by another node.
- **Sessions cannot regain stale privilege.** Delayed identity requests are
  invalidated across account changes, failed logins roll back local state, and
  password changes immediately end the revoked session.
- **Frontend mutations are race-safe.** Duplicate submits, stale modal state,
  tunnel toggles, imports, and catalog purchases stay synchronized with their
  server result.

### Tests

- Added SQLite/PostgreSQL parity and failure-injection coverage for authorization,
  transaction rollback, catalog revisions, traffic accounting, node reports,
  transitions, and dependent deletes.
- Added browser interaction regressions for authentication, groups, users,
  rules, tunnels, plans, purchases, traffic conversion, and install commands.

## [1.3.5] - 2026-07-20

### Changed

- **Rule and tunnel dialogs now use compact, responsive form rows.** Modal
  content shrinks within the viewport, tunnel status and sharing controls are
  presented in one concise settings bar, and route guidance is available from
  contextual help instead of occupying permanent form space.

### Fixed

- **Long forms no longer show nested or accidental horizontal scrollbars.**
  Target rows, tunnel hops, automatic ports, fixed ports, and multi-hop paths
  stay within the dialog width while viewport scrolling remains available for
  genuinely long forms.
- **Dynamic tunnel hops no longer spread React list keys through form props.**
  This removes the React runtime warning while preserving stable field state.

## [1.3.4] - 2026-07-20

### Changed

- **Configuration protocol is now 9.** Live preset-tunnel route and port
  changes use a two-phase handoff: nodes pre-stage the replacement path, begin
  accepting it after a short activation window, and retain the previous
  generation only long enough for established streams to drain.
- **Administrative forms are denser and less repetitive.** Tunnel and target
  editors use compact responsive rows, user actions are grouped into a menu,
  verbose guidance is moved to contextual help or removed, and rule tables show
  preset names without duplicating their full path.
- **Plan tunnel access is visible.** Plan tables and editors now show the shared
  tunnels implied by the plan's authorized entry lines, keeping the existing
  authorization model while making the effective permission explicit.

### Fixed

- **Changing a live tunnel no longer creates a remove-before-add outage.** The
  panel persists bounded staging/overlap leases transactionally, broadcasts the
  prepared snapshot, and sends a second activation snapshot after five seconds;
  old TCP streams can drain for up to sixty seconds without accepting new work.
- **Safety revocations still take effect immediately.** Pausing a rule,
  disabling or unsharing a tunnel, deleting a route, or rotating a device-group
  credential overrides every transition lease and closes the affected old
  generation instead of preserving it for availability.

### Tests

- Added SQLite/PostgreSQL parity coverage for transition creation, expiry,
  rollback, fresh-port allocation, and authorization revocation, plus node
  manager tests for staged entries, shared-listener overlap, natural drain, and
  termination precedence.

## [1.3.3] - 2026-07-20

### Added

- **Reusable preset tunnels share one internal TCP port per downstream hop.**
  Administrators can define a 2–8 group entry → relay → exit path once and bind
  multiple TCP, UDP, or `tcp_udp` rules to it. Public entry ports and per-rule
  targets, limits, load balancing, connection controls, and billing remain
  independent while the internal relay listener and route table are reused.
- **Tunnel sharing follows the existing device-group authorization model.** New
  tunnels default to administrator-only; enabling sharing only exposes them to
  users whose plan already authorizes the tunnel's entry group. The API
  revalidates the final rule owner transactionally, so guessed tunnel ids and
  stale administrator forms cannot bypass authorization.
- **Tunnel management and diagnostics.** The administrator UI manages paths,
  automatic/fixed internal ports, enablement, sharing, binding counts, and a
  firewall checklist. TCP diagnosis sends an authenticated probe through every
  shared hop to a panel-configured final target.

### Changed

- **Configuration protocol is now 8.** Shared listeners use a fixed client-first
  HMAC header with timestamp and replay protection. Device-group token rotation
  revokes active and retired authenticated generations; payload bytes remain
  unencrypted and still require end-to-end TLS or WireGuard when confidential.
- **Dashboard long-range charts retain real one-minute bandwidth peaks.** The
  7-day and 30-day views no longer average short spikes away, and tooltip titles
  display localized clock times instead of raw millisecond timestamps.

### Fixed

- **Path changes drain safely without cross-rule disruption.** New connections
  switch immediately, existing TCP streams drain on the old generation, UDP
  warm channels reconnect, and pause/disable/unshare/restart cancel only the
  affected rule or tunnel instead of every route sharing the port.
- **Tail traffic remains attributable across entry moves.** SQLite and
  PostgreSQL create bounded old-entry billing leases from the transaction's
  pre-update tunnel state, including an entry move combined with disable or
  unshare, and preserve every lease beyond query chunk boundaries.
- **Traffic snapshot commits cannot consume a recreated rule counter.** An
  in-flight report is now tied to the exact counter generation it observed, so
  rapid listener removal/recreation cannot underflow or erase newer bytes.

### Tests

- Added SQLite/PostgreSQL migration, authorization, port-allocation, and atomic
  rollback parity; real shared-port TCP/UDP/`tcp_udp` isolation and three-hop
  authenticated probe coverage; credential-revocation, replay, drain, and
  dashboard peak regressions.

## [1.3.2] - 2026-07-19

### Added

- **The administrator dashboard now retains and visualizes operational history.**
  A minute sampler persists UTC upload/download rates, connection peaks, and
  online/recent node counts for 30 days. The new admin-only history API serves
  1-hour, 24-hour, 7-day, and 30-day ranges with range-appropriate aggregation.
- **Dashboard health and ranking charts make the current fleet easier to scan.**
  Group health distinguishes fully online, partially online, offline, and
  never-reported groups; live group bandwidth and cumulative forwarded rule
  traffic are ranked separately so machine-NIC and RelayPanel byte counters are
  never presented as the same metric.

### Changed

- **Dashboard charts are responsive and administrator-only on the client too.**
  The mobile layout is single-column, history gaps remain visible, loading,
  empty, and failure states are independent, and the chart runtime is loaded
  only after an administrator enters the dashboard.

### Fixed

- **Historical statistics survive restarts and concurrent minute samples.**
  SQLite and PostgreSQL now safely deduplicate old placeholder rows before
  adding the natural series/time unique key, atomically upsert minute samples,
  and clean only expired dashboard rows.

## [1.3.1] - 2026-07-19

### Fixed

- **Rule updates are authorized and committed as one operation.** The effective
  chain entry is always derived from and checked against `hops[0]`, conflicting
  topology fields are rejected, and scalar fields, hops, targets, limits, and
  tunnel profiles now update in one SQLite/PostgreSQL transaction with rollback
  coverage.
- **Password work no longer blocks Tokio workers.** Login, registration,
  password changes, resets, and admin-created users share a bounded blocking
  bcrypt pool, with public registration and password-change rate limits.
- **Partial listener recovery preserves the rule's aggregate rate limit.** A
  recovered TCP or UDP half of a `tcp_udp` rule rejoins the existing shared
  bucket instead of receiving an independent fresh allowance.

### Tests

- CI now requires real two-hop and three-hop TCP, UDP-over-UOT, and mixed
  `tcp_udp` forwarding, including TCP Fast Open configuration and single-count
  traffic accounting.

## [1.3.0] - 2026-07-19

### Added

- **Advanced target selection and health management.** Multi-target rules now
  support weighted, round-robin, random, lowest-latency, least-connections, and
  failover selection. Nodes actively probe TCP reachability and latency, track
  DNS health, apply circuit breakers, and feed connection/capacity/anomaly
  telemetry back into routing decisions.
- **Authenticated UOT for multi-hop UDP and `tcp_udp` rules.** UDP-over-TCP is
  available on every inter-node hop, including mixed TCP/UDP rules. Each tunnel
  uses a dedicated persisted port and HMAC challenge-response authentication;
  the derived token is never transmitted on the wire.
- **TCP Fast Open on inter-node TCP paths.** TCP and the TCP half of `tcp_udp`
  chains can carry initial data in the SYN when Linux and the route support it,
  with a safe ordinary-TCP fallback when they do not.

### Changed

- **UOT and TCP Fast Open default to enabled.** Operators can independently
  roll either path back with `RELAY_ENABLE_UOT=false` or
  `RELAY_ENABLE_TCP_0RTT=false` during a mixed-version or emergency rollout.
- **TCP listener queues are consistently sized to 4096.** Ordinary listeners
  and Fast Open listeners now use the same backlog, avoiding the previous
  1024/4096 mismatch under connection bursts.
- **Config protocol version is now 7.** Panel and node must be upgraded
  together for the new routing, UOT, and Fast Open configuration.

### Fixed

- **Existing SQLite and PostgreSQL installations migrate safely.** Schema
  changes for target health, routing state, and UOT ports are ordered so an old
  database can start and upgrade without an index referencing a not-yet-added
  column. Migration regressions cover both repositories.
- **Rule and hop writes are atomic.** Failed multi-hop creation or replanning no
  longer leaves partial rules, ports, or hop rows behind.
- **UOT tunnel cancellation cannot desynchronize later frames.** A cancelled
  request drains its frame before the shared stream is reused, and slow or
  unauthenticated peers are bounded so they cannot consume tunnel capacity
  indefinitely.
- **Authentication throttling is preserved and hardened.** Login rate limits
  remain effective across router state rebuilds, while expensive password
  verification is globally bounded.

### Tests

- Main-branch CI now requires PostgreSQL migration/contract tests, debug and
  release end-to-end runs, and a Linux TCP Fast Open assertion that verifies
  SYN data on both the userspace and zero-copy forwarding paths.

## [1.2.3] - 2026-07-18

### Fixed

- **Restarting a SQLite-backed panel no longer pauses every current multi-hop
  rule.** The historical v0.4.7 chain-removal migration runs idempotently on
  each SQLite startup; after chain mode was reintroduced in v1.2, its old
  `route_mode = 'chain'` update also matched the new format. It now pauses only
  legacy chain rows without `forward_rule_hops`, while hop-backed v1.2 rules
  remain active across panel restarts. A restart regression test pins this
  behavior.

## [1.2.2] - 2026-07-18

### Added

- **A single device group can now act as both entry and egress.** The new
  `both` group type is selectable anywhere an inbound or outbound group is
  accepted, so one server needs only one node process even when rules enter
  and leave through that same machine. Config generation deduplicates the
  group while still installing every listener required by a multi-hop route.

### Changed

- **Responsive layouts now remain usable on narrow screens and compact
  desktops.** Rule tables use stable minimum column widths and compact action
  controls on desktop, switch to readable cards on mobile, and the shared
  layout, forms, filters, dialogs, and pagination now avoid clipped content or
  awkward single-character wrapping across the panel.

## [1.2.1] - 2026-07-18

### Fixed

- **Chain rule diagnosis now covers every hop.** `POST /rules/{id}/diagnose`
  dispatches to all hop groups (entry → mid → exit), not only
  `device_group_in`. Intermediate/exit nodes may report results (group
  membership check accepts any hop on the rule). The UI shows each hop's
  listener and its next-hop / final-target TCP probe.
- **Updating only `target_addr` / `target_port` no longer silently leaves
  stale `forward_rule_targets` rows.** Node config prefers the targets table;
  a scalar-only edit now rewrites that table so exit-hop forwarding follows the
  new destination.

## [1.2.0] - 2026-07-18

### Changed

- **Brand / distribute under `aict666/relay-panel`.** Install scripts, docs,
  update checks, node self-upgrade, and GHCR image names now point at
  `github.com/aict666/relay-panel` and `ghcr.io/aict666/relay-panel-*`
  instead of the upstream MoeShinX coordinates.

### Added

- **Multi-hop forwarding chain.** Rules can use `route_mode=chain` with an
  ordered hop list (entry → mid… → exit → final targets). The panel allocates
  per-hop listen ports, emits listeners on every hop group (including `out`),
  and sets `count_traffic` so only the entry hop is billed. Protocol version
  bumped to 5 (panel and node must upgrade together).

### Fixed

- **The connection cap is no longer offered on UDP-only rules.** It is enforced
  at `accept()`, which UDP doesn't have, so the panel would store the number and
  ship it to the node where nothing reads it. The field is now disabled for a
  UDP-only rule with a note saying why; a `tcp_udp` rule keeps it (it governs
  the TCP half).
- **Batch restart no longer blames the wrong thing on partial failure.** It
  reused the batch-resume message ("unauthorized lines can't be resumed"), which
  has nothing to do with a restart — it now names the real causes (paused rule,
  or nodes offline / too old).

### Added

- **Rule restart (manual + batch).** `POST /rules/{id}/restart` drops every
  connection a rule is currently carrying and rebuilds its listeners on each
  node of its inbound group. Owner-scoped (a user may restart only their own
  rules); batch restart is the frontend calling it per rule, matching batch
  pause/resume, so there is deliberately no bulk endpoint. The rule's `paused`
  flag is never read or written — a restart is not a state transition. A paused
  rule is rejected rather than reported as a hollow success: it has no listener
  to restart, and the user's actual intent there is "resume".

  This is deliberately NOT implemented as pause+resume. That pair leaves the
  rule PAUSED if the resume half fails (node offline, authorization revoked
  between the two calls, panel restarted mid-way) — an outage caused by the
  button whose whole job is to end one. It also frees the listen port for
  auto-assignment during the gap, and writing `paused` resets `auto_paused`
  (v1.0.8), corrupting the system-paused vs. human-paused distinction.

  The response's `restarted` field counts nodes ACTUALLY reached and can be 0
  on an otherwise successful request (every node too old or offline), so the UI
  keys its message off that rather than the envelope code — a restart that
  silently did nothing would otherwise be undetectable.

- **Scheduled rule restart.** A rule with `auto_restart_minutes > 0` has its
  connections dropped on that interval. The `max_connections` cap is the actual
  fix for connection accumulation; this is the valve for when you'd rather shed
  than refuse.

  The schedule lives in MEMORY, not the database. Persisting `last_restart_at`
  would mean every rule whose interval elapsed while the panel was down comes
  due at once on boot — a panel upgrade would begin by dropping every
  auto-restart rule's connections simultaneously. In-memory re-bases each timer
  to "now" on restart; the cost is at most one skipped cycle, which is invisible
  next to an unscheduled mass disconnect. A rule seen for the first time is
  baselined, never restarted on the spot.

- **Rule connection controls, storage + API** (no enforcement yet — the node
  half lands separately). Two new per-rule settings, both `0` = off/unlimited so
  an upgrade changes nothing until a rule is explicitly opted in:
  - `max_connections` — cap on concurrent TCP connections, scoped PER NODE.
    Nodes share no state and a group-wide total would need a central allocator
    on the forwarding hot path, so a rule served by 3 nodes admits up to 3x this
    number. The panel ships it to nodes in `ListenerConfig`; a node that doesn't
    understand it ignores it (`#[serde(default)]`).
  - `auto_restart_minutes` — interval for scheduled restarts. A non-zero value
    below `MIN_AUTO_RESTART_MINUTES` (5) is rejected: a shorter loop would drop
    connections faster than clients can reconnect, turning the safety valve into
    the outage.

  Both are edit-only. The atomic create path (`create_rule_with_guard`) doesn't
  carry them, so offering them at create would silently discard the value.
  `PUT /rules/{id}` defaults an omitted one to the rule's CURRENT value rather
  than to 0 — otherwise setting only `max_connections` would silently switch off
  that rule's scheduled restart.

### Compatibility

- Nodes below **1.2.0** silently ignore the unknown `restart_rule` message. The
  panel gates on `node_supports_restart_rule` and surfaces those nodes as
  "upgrade required" rather than counting them as restarted — a restart that
  quietly did nothing would be undetectable to the operator. Node Status already
  offers one-click upgrade.

### Schema

- SQLite Migration **38**, PG revision **21** (`PG_SCHEMA_VERSION` 20 → 21):
  `forward_rules.max_connections` and `forward_rules.auto_restart_minutes`, both
  `NOT NULL DEFAULT 0`. 0 = unlimited/off. A pre-v1.2 rule must come out
  UNCAPPED — if 0 reached a node as a real cap, upgrading would throttle every
  existing rule to zero connections; `max_connections_zero_means_unlimited_on_the_wire`
  pins that.

---

## [1.1.3] - 2026-07-16

### Fixed

- **systemd-managed nodes are no longer wrongly shown as "手动运行" (manual) in
  node status, and their one-click upgrade button now appears.** The node
  correctly reported its `install_method` ("systemd" | "docker" | "manual"), but
  the panel's status-report handler dropped the field when persisting the node
  status, so the frontend always saw it as unset and resolved every node to the
  "manual" upgrade state — showing "手动运行：不支持一键升级（退出后无人拉起）"
  and hiding the upgrade action on legitimately systemd-managed nodes. The panel
  now persists `install_method`; no node re-install is needed — an already
  running node surfaces the correct state on its next status report.

### Changed

- **The panel Docker image is now multi-arch (`linux/amd64` + `linux/arm64`).**
  ARM64 servers can pull and run the panel image directly. Each architecture is
  compiled natively on its own GitHub-hosted runner (no QEMU / cross-toolchain);
  the two per-arch images are merged into one manifest and the release verifies
  both architectures are present. Node binaries already supported amd64/arm64.

## [1.1.2] - 2026-07-12

### Fixed

- **Auto-assigned listen ports now respect the device group's `port_range`.**
  When a rule was created with the port left on `auto`, the panel ignored the
  inbound group's configured `port_range` entirely and always drew from a
  hardcoded 10000-65535 — so a group set to e.g. `65000-65100` still handed out
  2xxxx ports. Auto-assignment now draws from the group's `port_range`: an
  explicit range is honored verbatim (including sub-10000 ports the admin opted
  into), while the unset/default `1-65535` sentinel maps to the safe 10000-65535
  pool so a never-customized group never auto-assigns a system port. Manual port
  entry, per-group/per-socket-type conflict detection, and the frontend's
  `10000-65535` default display are unchanged.
- **A full port range now returns a clear error instead of "数据库错误".** When
  every port in a group's range is taken, rule creation returns a 400 naming the
  exhausted range (`设备组端口范围 X-Y 已全部占用…`) rather than a generic 500.

## [1.1.1] - 2026-07-08

### Changed — panel & node now release on independent tracks

- **A panel update no longer rebuilds or republishes the node.** Panel releases
  are tagged `vX.Y.Z` and node releases `node-vX.Y.Z`; the two version numbers
  no longer have to match. The `v*` tag builds ONLY the panel image + panel
  GitHub Release; the `node-v*` tag builds ONLY the node binaries + node image
  + node GitHub Release. `relay-panel-node:latest` is untouched by a panel
  release, and vice versa. (`docker-release.yml` is now panel-only; a new
  `node-release.yml` handles the node track; `binary-release.yml` was removed.)
- **The Dockerfile compiles only what each image needs** (`panel-build` /
  `node-build` stages with per-crate `cargo build -p …`), so a panel image
  build no longer compiles `relay-node`.
- **`release-check.sh` takes a `panel` / `node` subcommand:**
  `bash scripts/release-check.sh panel 1.1.1` checks only the panel version
  locations; `… node 1.1.0` checks only the node locations. A panel release no
  longer requires `crates/node` to match, and a node release no longer requires
  the panel to match. A bare version still defaults to panel (backwards
  compatible). `docs/VERSIONS.md` documents the two independent version sets.
- **`docker-compose.release.yaml`** uses independent `RELAYPANEL_PANEL_TAG` /
  `RELAYPANEL_NODE_TAG` overrides so a panel upgrade leaves the node image pin
  unchanged.

### Fixed — node version is no longer measured against the panel version

- **`/system/version`** now returns `latest_node_version` (highest `node-v*`
  tag) and `node_version_check_failed` alongside the panel `latest_version`.
  The node-status UI compares each node's `node_version` against
  `latest_node_version` — NOT the panel version — so a panel-only upgrade (e.g.
  panel 1.2.0 with node still on 1.1.0) no longer makes a current node look
  outdated or offers a non-existent 1.2.0 node upgrade.
- **The directed node-upgrade command** targets `latest_node_version`, not the
  panel's own version. If the node-version lookup fails, the upgrade endpoint
  returns 503 instead of falling back to the panel version (a panel-only
  release can never command a node to download a non-existent asset).
- **Protocol-incompatible nodes** now show "protocol incompatible" in the
  upgrade column too (previously only the status column did), taking priority
  over the version status. **A failed node-version check** shows a neutral
  state instead of a wrong green check or upgrade button. **A node newer than
  the latest node release** is shown as a "leading build" and never downgraded.
  The mobile node list now has the SAME upgrade affordance (version tag +
  upgrade button / docker-hint / manual-disabled / offline-disabled / protocol-
  incompatible ladder) as the desktop table, via a shared `resolveNodeUpgrade`
  helper so the two views can't drift — and it compares against
  `latest_node_version` like the desktop, never the panel version.
- **Node self-upgrade download URLs** use the `node-v{version}` path from 1.1.1
  onward, with a bounded fallback to the legacy `v{version}` path for 1.1.0 and
  earlier (where those binaries were originally published). The
  `relay-node-install.sh` installer queries the latest `node-v*` tag from
  GitHub (never guessing the panel version), supports `--version X.Y.Z`, and
  skips re-download/restart when the installed binary already reports that
  version.

### Fixed — node release gating & installer re-bind

- **`:latest` and the published GitHub Release are now promoted only AFTER
  verification passes.** The node release workflow previously pushed
  `:X.Y.Z` and `:latest` in one build step AND created the GitHub Release as
  stable + `make_latest: true` before `verify` ran — so a release whose image
  reported the wrong version (or whose binary failed sha256) had already
  repointed `:latest`, marked a broken node version as the repo's "Latest"
  (hijacking the README's "latest panel version" badge), and left an advertised
  stable Release behind. Now: `docker-node` pushes the version tag only;
  `build-and-upload` creates the Release as a **draft** (`draft: true`) — GitHub's
  public `/releases` list omits drafts, so a verify-failed node version can
  never leak into the panel's `latest_node_version` (`ALLOW_PRERELEASE_UPDATES`
  includes prereleases, and the installer doesn't filter them, so a prerelease
  would have leaked); `verify` runs (sha256 + binary `--version` + image
  `--version`) and is authenticated so it can still download the draft's assets;
  only then does `promote-latest` re-tag the verified `:X.Y.Z` image as
  `:latest` (`docker buildx imagetools create`) and `publish-release` publish
  the Release (`draft: false`, `prerelease: false`, `make_latest: false`). A
  failed release stays an invisible draft and never moves `:latest` or the repo
  Latest pointer.
- **Re-running the installer at the same version now refreshes the panel binding
  and systemd unit instead of exiting.** Previously an "already at version X"
  detection exited immediately, so re-running with a new `-t`/`-u` (to repoint
  the node at a different panel or rotate its token) silently did nothing. Now
  only the binary download/swap is skipped; the start script (PANEL_URL /
  NODE_TOKEN), the env file, and the systemd unit are rewritten and the service
  is restarted, so the new panel address/token take effect without touching the
  binary.
- **The installer now reports the version it actually installs** (the resolved
  `TARGET_VERSION`, which may come from `--version`), not the script's bundled
  `SCRIPT_VERSION`, in its download/summary/checksum-failure messages.

### Changed — UI, mobile, performance, accessibility (PR4)

- **Mobile node list now shows the version + a one-click upgrade affordance.**
  The mobile card mirrors the desktop upgrade ladder exactly (already-latest →
  green check; systemd+behind+online → upgrade button; docker → "update image";
  manual/unknown → disabled; offline → disabled; protocol-incompatible → red
  tag), via a shared `resolveNodeUpgrade` helper so the two views can't drift.
  Non-admins see no upgrade UI.
- **Pages are now code-split.** Every page (`Dashboard`/`Rules`/`Users`/`Plans`/
  `Groups`/`NodeStatus`/…) loads via `React.lazy` on first navigation, so the
  login page no longer pulls in the admin pages. Vendor libs are split into
  their own chunks (`react-vendor`, `antd`, `icons`, `semver`). The login entry
  chunk is ~115 KB (was the whole app); the heavy antd chunk is isolated and
  caches independently.
- **Cleaned up real Ant Design v6 deprecation warnings** (verified by running
  the test suite first): `Drawer width` → `size`, `Alert message` → `title`,
  `Space direction` → `orientation`. Also silenced the known jsdom
  `getComputedStyle(pseudoElt)` "Not implemented" noise in the test setup by
  dropping the pseudo-element arg (a targeted fix — real console warnings are
  still surfaced).
- **Accessibility.** Icon-only buttons (rule target move-up / move-down / delete,
  node upgrade, install-command copy) now have `aria-label`s. Login and Register
  inputs carry an `aria-label` instead of relying on `placeholder`. Async result
  regions (import results, diagnose loading) use `aria-live="polite"` /
  `aria-busy`. Mobile upgrade tap targets are ≥32×32 px.

### Changed

- **The minimal share-export now has a regression test pinning its round-trip.**
  The export format (`[{"dest":["host:port"],"listen_port":10000,"name":"…"}]`,
  enabled targets only, IPv6 bracketed) and the import validation previously
  lived as private functions inside `Rules.tsx`, so a future change could have
  silently broken the "export pastes straight back into import" property. They
  are extracted into a pure `frontend/src/utils/rulesIO.ts` module
  (`buildExportJSON`, `validateImportEntry`, `parseDest`, `ruleTargets`) and
  covered by `rulesIO.test.ts`, which asserts that a rule exported by
  `buildExportJSON` always re-imports cleanly (every entry passes
  `validateImportEntry`, and the parsed targets match the original enabled
  targets) for single/multi target, IPv4/IPv6, disabled-target filtering, and
  whitespace-trim cases. `Rules.tsx` now imports the shared helpers (removing
  the duplicated dest regex).

### Fixed

- **Creating a forward rule no longer cross-writes into a different rule when
  two inbound groups reuse the same listen port.** Previously, after the rule
  row was inserted, the new rule's id was recovered by re-querying
  `(owner_uid, listen_port)` — which ignored `device_group_in`. Because the
  port-uniqueness constraint is *per inbound group*, two rules on two groups
  can legally share a port, and the lookup returned the wrong (first) rule,
  so its targets, load-balance strategy and rate limits were overwritten. Rule
  creation now does the row INSERT + targets + load-balance strategy + rate
  limits + tunnel profile in a **single transaction** and takes the new id
  directly from the INSERT (SQLite `last_insert_rowid()` / PostgreSQL
  `RETURNING id`), so any mid-creation failure rolls back completely (no
  half-rule) and the side-tables always land on the right row. Existing
  port-conflict, `max_rules` quota and ownership checks are unchanged.
  (`create_rule_full` on the Repository trait, used by `create_rule`.)
- **Every password input now enforces the backend's 8–72 UTF-8-byte rule.**
  Previously MainLayout / Account change-password and the admin create-user form
  used an antd `min: 6` *character* rule (UTF-16 code units, no upper bound),
  while Register / ForcePasswordChange / admin-reset used a copy-pasted
  TextEncoder byte check — so a 6-char password could be set via change-password
  but never re-set via self-service, and a >72-byte password passed the client
  only to be rejected by bcrypt. All six inputs now share one
  `validatePassword` util (`frontend/src/utils/password.ts`) that counts UTF-8
  bytes via `TextEncoder` (exactly matching `password.len()` in Rust), and the
  zh/en hint text is unified to "8–72 bytes (UTF-8)".
- **`validateImportEntry` now runtime-type-checks every field** of the pasted
  JSON (it receives `unknown`, straight from `JSON.parse`). A malformed paste —
  e.g. `{"name": 123, "listen_port": "80", "dest": "1.2.3.4:80"}`, a bare
  primitive, `null`, or an array where an entry object was expected — now
  produces a clean per-entry "❌" error in the import results instead of
  throwing (`.trim is not a function`, etc.). `handleImport` likewise labels
  non-object entries safely and only casts via the new `asValidatedEntry`
  helper after validation. Covered by 9 new "anomalous input does not crash"
  tests.

### Security

- **Security response headers are now set on every panel response** (API + the
  static SPA): `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `X-Frame-Options: DENY`,
  a strict `Content-Security-Policy` (`default-src 'self'`, `script-src 'self'`,
  `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`,
  `form-action 'self'`), and a conservative `Permissions-Policy` (camera,
  microphone, geolocation, USB, etc. disabled). `style-src` is widened to
  `'self' 'unsafe-inline'` because Ant Design v6 injects runtime CSS-in-JS;
  `script-src` stays strict (Vite's production build has no inline scripts).
  HSTS is intentionally NOT set by the panel — it belongs to the HTTPS / reverse
  proxy layer (Caddy). Each header is `if_not_present`, so a stricter header set
  by an edge proxy is preserved.
- Pinned by regression test: a freshly-registered user has **no usable device
  groups** by design (`all_device_groups = false`, `user_device_groups` empty),
  so they cannot forward until a plan or admin grants authorization. Covered
  on both SQLite and PostgreSQL to guard against a future auto-grant-on-register
  change flipping this silently.
---

## [1.1.0] - 2026-07-02

Minor release headlined by **one-click remote node upgrades** from the panel,
capping off the plan-model / performance / correctness work of the 1.0.x line.

### Added

- **One-click node upgrade.** The Node Status page shows a per-node upgrade
  action (active when a node is behind the panel version). Clicking it directs
  that node to self-update: it downloads the panel's exact version from the
  official GitHub release for its architecture, verifies the published sha256,
  backs up its current binary, atomically swaps, and restarts (systemd). Safety:
  - The command carries no URL/binary — the node only pulls the official release
    and verifies the hash, so it can never be made to run arbitrary code.
  - **Upgrade-only:** the target must be a valid semver strictly newer than the
    running version, so a compromised panel can't force a downgrade to an old,
    vulnerable build.
  - **Install-aware:** only systemd nodes self-upgrade; docker nodes show
    "update the image", and manual runs are disabled (nothing would restart
    them). Nodes report their install method for this.
  - Single-flight + mandatory backup, so repeated clicks can't corrupt the
    binary and a failed backup aborts the swap.
- Node binaries continue to ship for both **amd64 and arm64** (static musl).

### Fixed

- The default "free" plan no longer reappears in the shop after every panel
  update. It is now seeded only on a fresh (empty) database, so an admin who
  deletes it (once other plans exist) won't see it come back on restart.
- Shop plan cards no longer render ragged when a plan grants no lines — the
  "granted lines" row now shows "无 / None" so all cards stay aligned.

---

## [1.0.9] - 2026-07-02

Finalizes the plan model to a **single current plan** (renew vs. switch), a
substantial **UDP/TCP forwarding performance pass**, and a round of correctness
fixes across billing, admin actions, and the rule editor.

### Changed

- **A user holds exactly one current plan.** Buying the **same** plan *renews*
  it (traffic stacks; a time plan's expiry extends from its current end). Buying
  a **different** plan *switches*: `traffic_limit` becomes the new plan's quota
  (not stacked), `traffic_used` resets to 0, the expiry is recomputed from now,
  and device-group authorization is fully replaced. The shop and the admin panel
  both confirm before a switch. This replaces the short-lived additive model —
  to give a user several lines, sell a bundled plan.
- **Rate-limited rules pick up limit changes without a node restart.** A rule's
  upload/download cap is part of the listener fingerprint now, so changing or
  clearing a limit hot-reloads the listener instead of running the old cap until
  the next restart.

### Added

- Shop plan cards resolve the **names** of the lines a plan grants server-side
  (previously they could show a raw `#id` for lines the buyer wasn't yet
  authorized for).
- **DNS cache** for outbound TCP targets: domain targets no longer re-resolve on
  every new connection, with a stale-entry fallback when the resolver blips.

### Performance

- **UDP forwarding.** Removed the per-packet full-table session scan; made the
  traffic counter lock-free (atomic per rule); moved the outbound bind/connect
  out of the session lock; sharded both the per-listener session map and the
  connection tracker (concurrent maps); and enlarged UDP socket buffers. Large
  reduction in per-packet lock contention on high-PPS links.

### Fixed

- **Traffic billing** is charged on upload **and** download (their sum × the
  line's rate); this is now documented explicitly.
- Plan **create** and admin **remove-plan** run as single transactions, so a
  mid-operation DB error can't leave a plan with no lines or a half-revoked user.
- **Batch rule delete** reports actual success/failure counts instead of always
  claiming every selected rule was deleted.
- List endpoints (plans / shop) return a real error on a DB failure instead of a
  fake empty "success" list.
- `update_plan` rejects setting `duration_days = 0` on a time plan.
- Editing only a Basic-tab field of a rule (e.g. the listen port) no longer
  wrongly demands "add a forward target".
- `relay-node-install.sh` no longer fails with a `getcwd` error when run from a
  directory that has since been deleted.
- The device-group edit form no longer offers the unused **outbound/egress**
  type; the inbound-group dropdown drops the redundant "(shared)" suffix; the
  rule list shows all target IPs on hover.

---

## [1.0.8] - 2026-07-01

A performance & correctness release for the node's TCP forwarding path
(latency/jitter fixes plus zero-copy for unlimited rules), a switch to
**replace-semantics** for plan-linked device-group authorization, and a small
round of admin UI polish.

### Added

- **Zero-copy TCP forwarding (Linux).** Unlimited rules now forward with
  `splice(2)` (kernel pipe, no userspace copy), cutting CPU and latency on long
  forwarding chains. Rate-limited rules keep the userspace copy path so the
  token bucket still applies; byte counters stay accurate on both paths.

### Changed

- **Plan authorization now replaces instead of only expanding.** Buying a plan
  sets the user's device-group authorization to exactly what the plan grants
  (a per-group plan resets `all_device_groups`; an all-groups plan clears any
  stale per-group rows). This supersedes the v1.0.7 "append-only / only ever
  expands" behavior, which could leave a downgraded user over-authorized.
- **Auto-paused rules resume symmetrically.** A new `auto_paused` flag marks
  rules the *system* paused (plan removal / expiry) versus ones a human paused;
  only the former auto-resume when authorization is restored, so a manual pause
  is never silently undone.
- **Larger forwarding buffer, smarter pacing.** The userspace copy buffer moved
  to 32 KiB and `TCP_NODELAY` is now set on every TCP socket (both accepted and
  dialed) to remove Nagle/delayed-ACK stalls that compounded across hops.
- **Admin UI.** The edit-user modal no longer exposes raw device-group toggles
  (authorization is driven by the plan); the plan expiry is editable only for
  time-based plans (grayed out for data plans); the delete-plan button is
  enabled only when a plan is selected.

### Fixed

- **Rate limiter head-of-line blocking & stall.** The limiter no longer holds
  its lock across the pacing sleep (one slow rule could stall others), and a
  chunk larger than the burst capacity no longer loops forever (debt-based
  tokens). This is the root cause of the reported forwarding jitter.

### Disabled

- **WS / TLS forwarding transports are no longer served.** The frontend already
  hides them; the listener code is kept in-tree but skipped at runtime. TCP and
  UDP are unaffected. (No config migration needed.)

---

## [1.0.7] - 2026-06-30

A feature release: a self-service **plan shop with billing**, a rewritten
**per-user device-group authorization** model, admin plan management, and a
round of rule/node UI polish.

### Added

- **Plan shop & billing.** Self-service plan purchase (`/shop`) with order
  history and account balance; admin plan CRUD (`/plans`). Buying a plan is an
  atomic balance charge.
- **User suspension.** A suspended user can still log in and buy a plan
  (buying does not auto-unsuspend), but forwarding is gated off.
- **Plan-linked device groups.** A plan can grant device-group access;
  purchasing auto-grants the authorization (append-only — it never silently
  removes access).
- **Device-group rate billing.** Each group has a multiplier (0.1–100); users
  are charged `real bytes × rate` while rule/user byte counters stay real.
- **Admin "edit user plan" panel**, embedded in the edit-user modal: assign an
  existing plan (charges the user's balance), change or remove the plan, and
  edit the expiry. Removing a plan also revokes the user's device-group
  authorization and auto-pauses (but does **not** delete) their rules.
- **Batch pause / resume** on the rules page.
- **Hidden device groups.** A per-group `hidden` toggle hides a group from
  regular users' Node Status page only — rules keep working (still selectable
  for new rules; existing rules forward and display normally). Admins are
  unaffected.

### Changed

- **Per-user device-group authorization replaces user permission groups.** A
  user is either unrestricted (`all_device_groups`) or limited to an explicit
  set of authorized groups; authorization only ever expands.
- **Removed the regular-user dashboard.** Its rules/traffic stats duplicated
  the 个人中心 (Account) page and its line/node counts duplicated Node Status;
  regular users now land on `/account`.
- **Rule form UX.** "TCP + UDP" is now first in the protocol list and the
  default for new rules; data-type plans hide the duration field; the two
  rate-limit inputs are labeled 上行/下行 with a tooltip explaining the
  shared-per-rule / enforced-per-node mechanism.
- **Node Status table** widened the IP column so IPv6 no longer misaligns the
  other columns; status/CPU columns compacted.
- **Rule export is now compact single-line JSON** (`[{…},{…}]`) matching the
  import box; the per-row export button was removed.

### Fixed

- **Deleting a plan no longer leaves residual device-group access.** Because
  authorization "only ever expands", a removed plan now also clears
  `all_device_groups` + `user_device_groups` and pauses the affected rules.
- **Resume-rule authorization bypass.** A restricted user could un-pause a rule
  on a device group they were not authorized for; `update_rule` now re-checks
  authorization on resume.
- **Regular user's rule edit** showed "未配置" for a shared group's connect
  host; it now resolves from the merged shared-group info.
- **Batch delete, admin rule isolation, and user-group UX** fixes.

---

## [1.0.6] - 2026-06-29

### Fixed

- **Rule export always returns a JSON array.** Single-rule exports previously
  emitted a bare object `{…}` instead of a one-element array `[{…}]`, making
  the exported JSON incompatible with the import box (which expects the array
  form `[{"dest":[…],"listen_port":…,"name":"…"}]`). Export now always wraps
  the result in an array, so copy-paste round-trips work regardless of the
  number of rules selected.
- **Imported rules were attributed to the admin instead of the target user.**
  When an admin opened a user's rule list via `/rules?owner_uid=X` and used
  the bulk-import feature, the created rules were owned by the admin account.
  The `owner_uid` parameter is now forwarded in the import POST request,
  matching the behaviour of the manual "add rule" form.

---

## [1.0.5] - 2026-06-29

### Fixed

- **Device-group node list crashed the page.** Expanding a device group threw
  `K.slice is not a function` and blanked the screen. The node-list ID column
  had no `dataIndex`, so antd handed the whole row object to `render()` instead
  of the `node_id` string. Now bound to `dataIndex: "node_id"`.
- **Default user-group remark mojibake.** The seeded default group's remark
  rendered as `Default group â?? all device groups allowed` on PostgreSQL
  connections whose `client_encoding` wasn't UTF-8, because the seed used an
  em dash (U+2014). Replaced with an ASCII hyphen across all four seeds (SQLite
  + PG, schema + migration); SQLite Migration 31 / PG revision 14 normalizes the
  remark on existing databases.
- **PG migration for the remark fix never ran.** `PG_SCHEMA_VERSION` was still
  13, so the early `current >= PG_SCHEMA_VERSION` guard skipped the new
  revision-14 UPDATE. Bumped to 14 so the migration executes and the baseline
  seed assertion passes.
- **TCP egress failures were undiagnosable on multi-NIC nodes.** `handle_tcp_connection`
  collapsed every per-target failure into a flat "no target available",
  discarding the real cause. Each attempt now preserves its classified outbound
  error (DNS / timeout / connection refused / source-bind), and the final
  log/error joins all per-target reasons.

### Changed

- **Node installer surfaces the dual-stack / egress env vars.** The generated
  `relay-node.env` now carries commented examples for `LISTEN_IPV4` /
  `LISTEN_IPV6` and `OUTBOUND_INTERFACE` / `OUTBOUND_BIND_IPV4` (illustrative
  IPs only, never defaults), so multi-NIC operators can discover them at install
  time. Defaults unchanged: dual-stack listen, system-routed egress, no source
  bind.

---

## [1.0.4] - 2026-06-26

### Fixed

- **Atomic group update + pause.** `update_user_group_with_pause` runs
  group update and rule re-evaluation in a single transaction. On pause
  failure, the group update is rolled back so the authorization state is
  NOT partially changed. Previously, a pause failure returned 500 but left
  the authorization change already written, causing some rules to continue
  forwarding with elevated access.

## [1.0.3] - 2026-06-26

### Fixed

- **Node-side traffic counter poison-pill.** When a rule was deleted, stale
  bytes in the node's `TrafficCounter` were never pruned. The next report batch
  was rejected atomically, the node kept retrying the same bytes, and traffic
  billing froze until node restart. The counter entry is now pruned when its
  rule disappears from the config and no live listener still references it.
- **Per-rule export button had no label.** The icon-only export button in the
  rules action column now shows 导出 / Export, matching its siblings.

### Changed

- **New 石墨靛蓝 / Graphite + Indigo UI theme.** Graphite sidebar, indigo accent,
  larger radii, hairline borders, flatter buttons — replacing the default
  deep-blue admin-template look. antd v6 token-driven; no business components
  touched.
- **Self-hosted Noto Sans SC (思源黑体)** as the UI font, for crisp and
  consistent CJK rendering across platforms.
- **Forced password-change notice reworded** (zh + en) to cover both the
  admin-reset and create-with-must-change cases, instead of only "an admin
  reset your password".

---

## [1.0.2] - 2026-06-26

### Fixed

- **PostgreSQL: creating a forward rule failed with `database error`.** The
  owner-scope ownership guard in `replace_rule_targets` decoded a `SELECT 1`
  literal as `i64`. PostgreSQL types integer literals as `INT4`, so sqlx
  rejected the `INT8`/`INT4` mismatch. SQLite's dynamic typing masked the bug,
  so it only affected PostgreSQL deployments. Now decoded as `i32`.

---

## [1.0.1] - 2026-06-25

First public release of RelayPanel.

### Highlights

- **TCP/UDP forwarding panel** with relay-node architecture, WebSocket
  real-time config push, and HTTP polling fallback.
- **Multi-plan registration.** Administrators configure which plans are
  available for registration; users pick a plan when signing up.
- **Per-target circuit breaker.** 3 consecutive connect failures → 30-second
  circuit break; all-down fails open (probe mode). Applies to failover and
  round-robin strategies over TCP/WS/TLS.
- **User rule management.** Administrators manage a user's rules directly from
  the user management page; ownership determined by entry point.
- **GeoIP node region display** with built-in primary (ipinfo.io) and fallback
  (ipwho.is) sources. GeoIP cache auto-cleaned on node deletion.
- **SQLite + PostgreSQL dual backend** with compile-time trait enforcement and
  CI-guarded test parity.
- **Dashboard** with node aggregation, traffic statistics, and quota management.
