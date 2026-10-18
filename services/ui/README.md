# Briareus Control Panel UI

This is one independently deployable **Vue 3 / TypeScript / Bun** frontend service.
Source, local dependency lock, Dockerfile, Docker-specific ignore, Nginx and
Coolify Compose are all in `services/ui/`. It owns no SQL data,
Identity credentials, Authorization grants or MCP Hand runtimes.

## Public paths

- `GET /` — static, indexable Briareus project landing from `public/_site/index.html`.
- `GET /robots.txt` and `/sitemap.xml` — public landing crawler files.
- `GET /panel/` and `/panel/assets/*` — Control Panel UI SPA, `noindex,nofollow`.
- `/api/*` — same-origin browser requests to the separate **Control Panel API**,
  NOT to Identity directly. Gateway routes API and Hands separately.

The browser calls **only same-origin Control Panel API** routes under
`/api/*`, never the provider Admin API or individual MCP Hands directly.
The canonical API revision is **`/api/v1`**. Identity operations (native
Init/capabilities/PoW/cancel, session/config/logout and current Platform
User/Project `me`) belong under `/api/v1/auth/*`. Resource APIs use their
own paths: `/api/v1/agent-sessions`, `/api/v1/approvals`,
`/api/v1/catalog` and `/api/v1/files/read`. The unversioned browser routes
are retired, with no rewrite, silent fallback or hosted-provider link.
The only exception is the **private OAuth return endpoint**
`GET /api/auth/oidc/callback`, pinned to Rauthy's existing registered
redirect URI and not called by the Frontend. Changing that callback requires
an independently coordinated Backend/Deployment OAuth client update.
Production `src/app/App.vue` now mounts exactly **one** login and Platform
composition, `OidcPanelPage`, instead of branching into the unreachable legacy
`PlatformPort` UI. The full verified User/Project workspace still requires
current BFF owner proof. That main workspace loads as an asynchronous JS
module; the initial static shell shows a localized, noninteractive status
until it is available. If the module asset fails during a Development
rollout, a bounded read-only error screen offers an **explicit reload**;
missing JS does not open a guest, old Identity or hosted-Rauthy path, and
there is no background retry of POST/authentication commands. Protected
AgentSession, Catalog, MCP module, Dashboard and Settings bundles are also
lazy-loaded **only when the parent has a current BFF User+Project proof**;
they provide their own noninteractive pending/failed states and manual reload.
A missing protected-section script is a presentation failure, never an
authorization fallback. Only an explicitly DEV-built source can load the
isolated local design preview; the production entry has no guest/legacy
Identity fallback or hosted-provider login action.

The default `/panel/` screen is now the **compact Briareus session-status
card inside the permanent Control Panel sidebar/header**, now with an
enabled native email/password form for an explicit user-triggered sign-in.
There is no separately exposed technical preparation button.
Anonymous navigation does not
open a guest MCP preview; direct protected hashes return to the sign-in
route. Current Rauthy OIDC session is checked read-only, with stable
in-place loader/status UI. The earlier custom Identity client/form has been
removed from this Frontend source.

**Current sign-in UI (P0):** The owner prioritized unblocking the
actual login form. The single Control Panel sign-in card now accepts email and
password and executes exactly one explicitly requested same-origin Backend
chain: GET /api/v1/auth/capabilities (rauthy-native-v1), POST /api/v1/auth/start
with an empty JSON body, POST /api/v1/auth/pow with an empty JSON body, the
official isolated sPoW Web Worker, and POST /api/v1/auth/first-factor with
email, password and solved PoW. There is no hosted provider redirect,
retired Identity route, browser-stored password, provider cookie or token,
automatic password retry or client-created Permission/Permit. The password
field includes an accessible show/hide control (keyboard and touch). A
rejected/expired/unavailable sign-in retains its typed password **only in
the current in-memory Vue component** so the user can check/correct it and
retry; it is never placed in storage, logs or URL parameters. The password
is cleared when a verified sign-in succeeds, when the user explicitly cancels,
or when the component is destroyed. There is no redundant 'Check session'
button during ordinary signed-out sign-in; only a lost/uncertain login result
or a failed initial session read exposes a contextual read-only retry.
Explicit cancellation is distinct from confirmed server-side cleanup; a
lost reply is not success.

Even HTTP200 from the first-factor endpoint is not Platform User access.
The component independently re-reads /api/v1/auth/session for the exact
signed Rauthy issuer/client/expiry proof. Its parent independently checks a
current /api/v1/auth/me User/Project membership proof before mounting
protected actions. Live Backend native capabilities now accept an optional
email OTP continuation, and the UI accepts only the exact v1 declarations
\`continuations:[]\` or \`continuations:["otp"]\`. This is a *provider
capability*, never a claim that a particular user needs OTP, or that a
password has been checked. Unknown/duplicate/overbroad continuations still
fail before Init. The exact Backend HTTP202 \`otp_pending\` with one or more
email methods is now classified as an MFA continuation (not a network error,
a cookie, or authenticated Platform access). The native OTP start/finish BFF
endpoints exist in current Backend source; the actual OTP entry/selection
UI remains an independent pending integration and is not synthesized here.
WebAuthn/ToS/account-update/client MFA or unsupported OTP variants remain
fail-closed, as does Backend HTTP409 requiring restart. The UI never silently
bypasses MFA or guesses a login result. Thus password-only source wiring
exists, but real Dev user/MFA/Project acceptance remains a mandatory gate.

A Rauthy PoW challenge has its OWN short expiry, distinct from the Init
transaction. In a public anonymous Development precredential check on
2026-10-16, provider-issued challenges were difficulty 19 with about 30s
remaining; the official Web Worker independently solved synthetic difficulty
19 tasks in Chromium within that window. Before the explicit credential POST,
the UI requires more than 1.5 seconds of proof validity based on both wall
and monotonic clocks, so a delayed worker or device clock rollback cannot
submit an already expired challenge. Backend still makes the definitive PoW,
first-factor, MFA and signed-cookie decision; solving PoW alone never logs in.

If a signed Rauthy session exists but /api/v1/auth/me is unavailable, the
Panel displays the Platform owner-unavailable state, not a false authorization
denial or current Project. A valid Rauthy session without a current User and
Project is not admin access.

Backend `GET /api/v1/auth/session` returns HTTP401 when no valid Secure
HttpOnly `__Host-briareus_oidc_session` cookie exists. Earlier published Dev
returned `{"detail":"OIDC browser session required"}`; current Backend
source now returns canonical `{"error":{"code":"OIDC_SESSION_REQUIRED"}}`
with `Cache-Control:no-store`. The UI safely treats EITHER HTTP401 as
`signed_out`, without decoding the unauthenticated body or making a redundant
provider `/config` request. A 401 after independently confirmed completed
authentication still requires Backend/Gateway session issuance and cookie
forwarding diagnosis. Frontend never substitutes a manufactured identity or
principal. Only HTTP200 with exact bound Rauthy session AND valid provider
configuration can advance identity; Platform User/Project remains a separate
BFF check. A late HTTP204 logout arriving after cancellation is an uncertain
result, not confirmed revocation.

The login status panel follows RauthySignIn's existing state event.
When the parent OidcPanelPage supplies a freshly checked Rauthy
session snapshot, the child adopts it without a second session/config
GET, timer poll or tab-visibility refresh; the parent retains all
session and Platform-membership revalidation. If standalone, the
RauthySignIn component still owns its own refresh and logout.
On confirmed logout, uncertain logout or expired current-user proof,
the parent invalidates the cached login snapshot so a newly mounted
sign-in screen cannot display a stale `signed_in` state. The UI must never
submit credentials through the retired Identity route, use OAuth ROPC,
invent a Rauthy login endpoint, or store passwords/tokens in JS storage.
Backend+Deployment own the versioned native first-factor contract and the
still-pending supported MFA completion and real User/Project acceptance.

All browser-facing authenticated Control Panel API clients now decode JSON
through a shared **bounded, cancel-aware stream** instead of unrestricted
`response.json()`: signed Rauthy session/config 8KiB, Project owner proof
256KiB, Catalog list 64KiB, bounded AgentSession/approval inventories 6MiB
(Backend permits up to 50 rows, 32 resources per row and 512 Unicode
characters per selector),
small management-command receipts 16–128KiB and error bodies 4KiB. Source DTO
shape, Project/actor, revisions and expiry remain checked independently.
Oversized, aborted, incomplete or malformed replies never turn into identity,
current owner permissions, confirmed approval/revocation or file bytes.
Aborting a stalled 200 or 503 body cancels its reader without waiting for
the remote proxy. This is a transport limit, not a new Cedar policy.


A child component echoing the same provider snapshot is not a new auth event.
A real logout or changed identity invalidates older owner reads before their
late response can restore the previous User. Starting logout removes action
widgets immediately rather than leaving them active while the cookie is being
revoked. An unconfirmed logout is unavailable, never still signed in.

`GET /api/v1/auth/me` is the independent short-lived (maximum 30s),
cookie-bound, Rauthy issuer/subject-bound **Briareus User/Team/Project proof**.
Once the real Backend owner adapter answers positively, `OidcPanelPage`
opens the full Briareus sidebar/dashboard/MCP layout and read-only
Team/Project identity views, preserving deep links. The UI revalidates
membership before expiry and on return to the browser. The selected Project
is shared across Home, Projects, AgentSessions, Integrations and Variables,
kept only while the same verified User retains the relevant permission, and
reset immediately when Rauthy changes principal or owner rights are revoked.
Catalog never treats that UI selection as an execution grant. Signed-out, denied,
invalid, expired or unreachable owner state returns to the login screen
without opening operations. **Sidebar visibility is presentation only** and
never a Cedar decision.

For the **first MVP landing screen**, the server-confirmed User/Team/Project
view is followed by one direct **Open AgentSessions** action instead of
placing an unavailable observability dashboard into the login-success
path. The button appears only for a Project with owner-reported
`use_resources` or `approve_agent_session`; it is disabled without those
rights. This is *visibility only*: each session, approval, creation or revoke
request still checks the current Project/owner action independently through
the BFF, and no rights or records are manufactured in Frontend. Advanced
dashboard/observability remains on its dedicated navigation route.

The Integrations and Variables navigation screens now consume the actual
LOCAL Backend `GET /api/v1/catalog?project_uuid=UUIDv4&kind=integration|variable`
read-only route for verified Resource Catalog nonsecret metadata. They show
only `resource_uuid`, `kind`, `owner`, canonical display `key` and
`version`, after a fresh Rauthy-bound Platform Project `use_resources`
proof. Team ownership is matched against both current Team membership and
selected Project owner. Strict shape checks reject foreign/overbroad rows
or any returned secret/credential/value field; no writes, credential leases,
variable values or invented MCP resource permits. Local DEV preview never
requests the Catalog BFF. The Resource owner source must still be deployed
with trusted peer verification before this view can show actual data.

Normal AgentSession creation, current Project-scoped session inventory,
approval queue and server-authorized revocation use their *own* same-origin
BFF routes and fresh membership checks. The per-session inspector consumes
`GET /api/v1/agent-sessions/{session_uuid}?project_uuid=...` using the
same owner-bound DTO validation as the inventory. It clears old content on
failed refresh, permission change, expired proof or a mismatched response.
Revoke uses the version from this exact-session GET, independent approver
proof and a canonical idempotency UUID, then confirms the exact session again.
A capped list, missing endpoint or absent row never proves that revoke succeeded. On passive deadline expiry, only the
elapsed active row is hidden from that owner's current snapshot; unaffected
sessions and historical records remain visible. This is presentation only,
not a browser-authored expiration/revocation decision.
A known canonical session UUID can be opened independently of the capped list.
Only HTTP404 with `AGENT_SESSION_NOT_FOUND` means a scoped missing/hidden
record; a generic missing route remains unavailable. After an ambiguous revoke
reply, one exact read may show the current state, but the UI labels that as an
observation, not as confirmation of the missing command receipt. No POST is
replayed. The original session remains directly inspectable when reconciliation
is unavailable.

No optimistic success, invented grant revision or client-made permit exists.
Session and approval responses also validate the six exact Runtime Hand
action/resource-kind pairings and deny forged, duplicate or incomplete
elevated effects. The management BFF client now additionally rejects
**unexpected fields** in successful current AgentSession and Approval records
and inventory envelopes, or unexpected properties on a newly opened normal
session receipt. This follows the exact Backend `_oidc_approvals.py` owner
projection and prevents silently accepting overbroad `permissions`, private
`access_token` or undeclared grant attributes; an invalid list cannot retain
stale actionable entries. No field is treated as a Cedar Permit. The live owner adapters still require independent
acceptance and source-backed resource picker DTOs before elevation requests. Reserved Files
`project-path-v1:<Project UUIDv4>:<path fingerprint>` selectors must belong to
the selected Project on every session/approval/elevation read or write.
Malformed/reserved aliases and cross-Hand use are rejected; the browser never
constructs these selectors from arbitrary paths or treats a digest as ownership. Legacy
`PlatformPort` remains fail-closed until complete per-service management
permissions and CRUD/streaming DTOs can be installed independently.
No UI-local claim or Rauthy subject creates a Project, grant or privilege.

### Operation continuity and upcoming Files integration

Normal-session creation is prepared as an immutable in-memory request intent.
If the response is lost, invalid or HTTP503, the Panel retains the original
serialized body and Operation-UUID/Idempotency-Key instead of starting another
creation. The explicit **Retry original request** action revalidates current
User/Project permission and resends precisely that intent. Pending parameters
and the new-create action are locked; navigating between tabs or Panel routes
does not replace the pending key. Receipt recovery is labelled as the result of
the original creation, not a new session or a current grant. Recovery stops
at the normal 24-hour session lifetime, before the owner's seven-day deduplication
retention boundary. A closed page, logout or different identity clears this
memory; there is no credential or request journal in browser storage.
The recovery limit uses both wall and monotonic clocks and latches expiry:
restoring the clock cannot revive an elapsed request. The shared command
orchestrator snapshots User/Project identity before verification, retains an
interrupted dispatch for its original owner, and does not erase an earlier
uncertain creation when a later retry is denied.
A creation/recovery receipt can open the exact current-session inspector
without another POST. This distinguishes the original creation from a later
revoked/changed session. Approved requests likewise link to their issued child
session through the same owner-checked point-read API. That read does not reuse
an approval as a grant; lost Project visibility or invalidated parent records
closes the inspector and discards its data.
Request details are also readable without approver privileges: initiator,
current request revision, exact operations/resources and resolution references
come from the current list response. Non-approvers only see their own requests;
an overbroad owner reply is rejected instead of being silently filtered.
Inspecting a request never starts a decision or an elevation request.

Refreshing a still-current `/me` proof for the same User/Project does not reset
a confirmed normal-session result or abort create/revoke/approval POSTs.
Changing the User, Project or required permission invalidates the old command;
expiry is still enforced independently. An open approval/revoke confirmation
survives a same-scope proof refresh only while its row and revision remain
current. Confirmation is disabled during revalidation and closes on a changed
revision, revoked action, failed read or lost owner scope. Approval decisions revalidate current
membership and re-read the exact approval revision before one idempotent POST,
then confirm status/revision/resolver through a fresh GET. A resolution must
advance exactly one submitted revision and preserve the original requested
effects. Pending receipts contain neither a resolver nor an issued session;
approved receipts name a different resolver and child session, while rejected
receipts cannot claim a child grant. A newly requested approval's returned UUID
must match its operation UUID. The final GET must also preserve the exact
requested effects and the issued child session from the receipt, not merely
its status and resolver. A lost response or server 5xx causes one read-only
reconciliation, never another POST. If the exact original request is present,
its state is labelled as observed, not as a confirmed command result. Absence
from the capped list, substituted effects or inconsistent revisions leave the
outcome uncertain and discard stale actionable rows.

The source-backed `requestSessionElevation` client prepares the actual
`POST /api/v1/approvals` contract: bounded exact Hand/resource tuples,
1–300 seconds, current grant revision and one operation/idempotency UUID.
It accepts only a matching `202 pending` result, not an elevated grant. No
component mounts this action until a genuine resource picker and fresh
User/Project checks exist. Local contract tests do not prove resource ownership.

Files navigation on both direct and nested MCP routes links to AgentSessions
only for the currently verified resource-capable Project. Upload, download,
write and read execution remain disabled without their BFF/Hand integration.
`FilePreviewPane` can decode a future owner `readResult` matching Runtime's
unpublished Files-read adapter (`path`, `size_bytes`, `sha256`,
`content_base64`). It bounds 262,144 bytes, verifies canonical relative paths,
base64 length/padding and SHA-256, distinguishes strict UTF-8 from binary, and
renders escaped text only. The complete accepted text is browsable in bounded
8,192-character fragments rather than silently ending at the first 64KiB.
Fragment boundaries preserve Unicode pairs and CRLF; literal case-sensitive
search covers the bounded input, with at most 500 retained match positions.
Binary data displays byte count and checksum metadata without rendering as text.
A new input, denial or invalid response clears previous content and search state. The checksum verifies byte consistency, not a
signature, resource ownership or a Cedar decision. No Files network endpoint
is invented or enabled by the preview; changing input/scope discards old data.
Raw `content` strings are accepted only in the DEV-only design workbench;
production file preview requires a checksum-validated owner response.

The Files screen now verifies the selected Project through exact
`GET /api/v1/auth/me?project_uuid=...`, then reads the existing bounded
AgentSession inventory. It displays only active, nonexpired `files.read` /
`read_file` resource tuples from parsed owner records, with source
session UUID, revision and opaque resource identifier. An action-only normal
session has no Files resource scope. The list may be capped at 50 sessions;
absence is not evidence of revocation or deletion. Losing Project permissions,
changed Project ownership/version, expired server proof or an aborted read
clears stale scope. Individual Files-session rows expire independently:
one elapsed row must not remove an unrelated still-current read-only row.
When the wall clock is rolled backward after the source snapshot, the
monotonic earliest-expiry timer still retires that exact elapsed row. A
clock rollback can never restore its display or imply renewed Files access.
This screen
never passes those opaque resource selectors to a Hand or claims Cedar Permit.
Backend now defines a **source-only** `POST /api/v1/files/read` facade with
bounded input `{project_uuid,agent_session_uuid,expected_grant_revision,
path,max_bytes}` and owner-verified `{path,size_bytes,sha256,content_base64}`
output. The typed Frontend client exists in
`features/files-preview/api/files-content.ts`, but is **not exported to or
invoked by the product UI**. The reader streams at most 384KiB of success
JSON, caps error JSON at 4KiB and cancels stalled body reads promptly upon
AbortSignal; oversized/error replies never enter unbounded `response.json()`.
It requires one exact current session, an owner-
supplied canonical Project-relative path matching a current
`files.read/read_file/workspace_path` selector, and it caps raw response bytes
before verifying SHA-256. A digest-only selector cannot be reversed to a path
in the browser. The Backend's trusted Files content owner is not yet wired,
so this endpoint correctly returns 503; no speculative file path field or
read button is enabled. BFF and Files Hand must independently recheck signed
Rauthy identity, Project, session revision, Cedar, mapping and expiry both
before and after filesystem IO. No browser-supplied Permit or private Hand URL
is accepted.

Local browser evidence must identify the served build. The Runtime integration
harness may serve its own pinned copy rather than this worktree's latest `dist`.
A successful rebuild alone does not update that copy. Candidate-static browser
fixtures and the actual Gateway-served UI are separate validation levels; API
fixtures must never be reported as authenticated Rauthy/Platform/Cedar acceptance.

Appearance preferences are RU/EN, dark/light, density, Graphite/Indigo/Amber
accents and sidebar state; these are display-only, never authorization.
Shadcn-vue's generated Reka UI primitives own the shared Button/Card/Input/
Sidebar/Tabs/Table/Popover/Select/Switch/Dialog/Badge components. FSD
navigation, module operations and the composite shell are owned by distinct
features/widgets with public imports; no module server operation is enabled
until a real scope-bound API exists.

## Local UI design workbench (development only)

To compare the Control Panel visual states without an identity service, run:

```sh
bun install --frozen-lockfile
bun run dev -- --port 43197 --strictPort
```

Open `http://127.0.0.1:43197/panel/?ui-preview=1#platform/mcp`.
This Vite **DEV-only** workbench allows navigation through module and settings
layouts, direct links such as `#platform/mcp/files/settings`, and explicit
loading/empty/denied/unavailable presentations. The
`#platform/sessions` route previews the shadcn tabbed Current sessions /
Approvals / Create session workspace, including server-shaped empty, loading,
denied and unavailable views, without fabricated users, records or grants.
The `#platform/mcp/web` preview has local-only sample browser tabs; the
`#platform/mcp/files` preview accepts a bounded browser-local text file and
never uploads its contents. It never installs a
`PlatformPort`, fabricates a User, enables tool calls, writes approvals or
issues auth tokens. Production bundles have no preview route.

Use a real browser at mobile and desktop viewports for UX acceptance. The
native build and an HTTP response alone are not screenshot/click acceptance.
`/panel/` without the dev query stays on the real sign-in screen.

## Local development on 127.0.0.1

Run the local service adapter from the repository root without rebuilding images:

```powershell
docker compose --env-file .local/briareus/secrets/stack.env -f docker-compose.local.yaml up -d --no-build
docker compose --env-file .local/briareus/secrets/stack.env -f docker-compose.local.yaml watch --no-up briareus-platform briareus-resources
```

In a separate terminal:

```powershell
cd services/ui
bun run dev:local
```

Open `http://127.0.0.1/panel/`. Vite serves the actual Vue source, including
its HMR WebSocket, and proxies `/api/` to the loopback BFF at port 18000.
The API reloads its mounted Python source; Compose watch restarts only the
selected owner when its mounted source changes. This requires the existing
local images and ignored `.local/briareus/secrets/stack.env` provisioning.
Normal service Compose files retain their deployment responsibilities.

`BRIAREUS_LOCAL_TESTING=1` explicitly selects the fixed HTTP browser origin
and HTTPS Rauthy issuer `https://127.0.0.1/auth/v1`. Provider TLS still uses
the local CA inside the application transport. No Windows certificate trust
change is needed. All published local development ports bind to loopback;
this opt-in is not a public Development configuration.
The local adapter sets Rauthy's `ADMIN_FORCE_MFA=false` so the existing local
administrator can provision development users without enrolling a passkey.

Local credentials are in the ignored, access-restricted
`.local/briareus/secrets/admin-credentials.json`; do not copy them into docs,
Git, URLs or command arguments. Rauthy owns the account and password. A fresh
Platform database requires explicit offline first-operator enrollment of the
verified existing Rauthy administrator, independently of provider login.

Operators manage named teams and projects through `/api/v1/platform/inventory`
and `/api/v1/platform/commands`. Team membership refers to real linked Rauthy
accounts; connecting an account uses its email and grants only the ordinary
Platform user role. Passwords and provider administrator roles are not managed
by these controls. Writes retain their operation UUID for safe retries.
Teams, projects and team memberships have no persisted `version` column or
version label in this UI. Renaming checks the previously displayed name;
owner operations read current authority under a transaction lock.

Browser sessions currently have an absolute maximum lifetime of 15 minutes.
Activity and membership polling do not extend login. Vite's development
WebSocket handles source updates; it is not an application data subscription.

## Local integration acceptance

Identify the exact served UI bundle before a browser run. The Runtime-owned
Gateway may serve a pinned UI copy rather than the latest `services/ui/dist`.
Do not restart Runtime's processes or silently substitute their source.

`tests/fixtures/peer-management-wire.py` launches the actual selected Backend
membership/management/Catalog routers on a dynamically allocated loopback port.
Run it with the Backend Python environment, an explicit `--backend-source`
path to its `services/api/src`, and an explicit `--bun` executable. Its sibling
TypeScript file calls the actual Frontend clients over HTTP: exact Project,
creation and idempotent recovery, session list/detail, elevation request,
approve/deny, revoke, Catalog and denied/conflicting/missing responses.
The fixture injects temporary in-memory session and owner sources. It is a
wire-contract check, not Rauthy, SQL or Cedar acceptance; it makes no writes
to those systems and stops its own server and child process afterward.
Neither file is imported by the application or creates a product route.

The retained `scripts/local-stack-readiness.py` and `local-oidc-start.py` are
**historical transport diagnostics**, not the current native-login acceptance
contract. They preserve exact former issuer/client and callback checks for
explicit investigation, but hosted authorize HTML or an old successful
checkpoint must not be interpreted as native first-factor/MFA readiness.
The current native UI contract is described at the top of this document.

## Standalone native build

From this directory:

```sh
bun install --frozen-lockfile
bun run build
bun run test  # persistent OIDC, current-session/revoke and approval contract tests
```

`dist/` is disposable generated output, never source-controlled. The source
has one Vite build with `/panel/` asset base and separate public files; no
extra Gateway HTML engine, Jinja or SSR service is installed.

## Coolify Development service

Existing Briareus Development application UUID:
`pxv5fbwcogun3va4vygnejd4` — rename display to **Control Panel UI**, but
reuse the SAME application (not a new instance).

- Base directory: `/services/ui`
- Compose file: `/docker-compose.coolify.yaml`
- Service-local Dockerfile: `services/ui/Dockerfile`
- Default Watch paths: `services/ui/**` **and** `services/external/**`.
  The latter is the owner-required directory-wide default for **all** services,
  not a manually curated list of vendor files. It does not add SQL migrations
  to UI or grant permission to edit the External stack.
- Existing private `briareus-net` remains. Canonical UI DNS is
  `briareus-control-panel-ui:8080`; Runtime/Gateway owns the atomic migration
  from any compatibility alias. Do not create a second UI or remove an active
  Gateway route before Runtime confirms the local DNS switch.
- Only Gateway owns the public `briareus.koba-nexus.ru` origin.

A UI-only edit must not build Control Panel API, Identity or the Hands.
Do not add SQL migrations, credentials, additional unapproved shared watches or public UI
secrets. Observe real Coolify deployment and `/`, `/panel/`, assets, sitemap,
then separately report any still-unavailable backend-authenticated API.

## MCP module migration

The legacy Browser, Files, Terminal, GitHub/GitLab, Analysis, Calls, OAuth,
Observability and service-tool **interface inventory** is preserved as
separate modules with nested settings **behind verified Platform access**.
File preview, repository grouping and observability provider panels show
honest unavailable states until read/write BFF DTOs and current grants exist.
Global display preferences are functional; backend module settings require
verified, provider-agnostic Control Panel API DTOs.
See `docs/services/ui/mcp-module-migration.md` for the evidence and missing
BFF contracts.

The small `tests/fixtures/files-preview.entry.ts` bundles only the existing
Files component for isolated local browser acceptance. It is not imported by
`src/main.ts`, adds no product route and makes no product API call. Building
that fixture separately allows browser validation without a concurrent Vite
server in a process-constrained workspace.

### Scoped inspection and lifecycle ownership

Catalog integrations and variables expose only the existing nonsecret metadata
GET. Project/Team owner filters and text search operate on the returned records;
the 50-record cap is explicit and no pagination endpoint or secret read is
invented. Record details follow the latest accepted list revision, survive a
same-scope proof renewal, and close when the record, identity or permission is
no longer present. A filter miss is distinct from an empty source response.

Catalog, session lists, approvals and creation share a small local proof-lifetime
primitive. The **parent Controller** additionally binds the current Rauthy
identity and User/Project owner proof to independent monotonic lifetimes, so
a wall-clock rollback cannot extend protected navigation/commands while an
asynchronous BFF renewal is stalled. Fresh owner reads acquire new bounded
leases; losing or changing identity clears both immediately. This guard
cancels expired presentation even with unchanged parent props, checks the
foreground deadline and never turns a local clock observation into Cedar
Permit. It is a UI invalidation guard, not a server permission.
The session and approval inventories now age individual actionable records:
one elapsed AgentSession or pending approval is removed from its current
presentation snapshot and any matching open confirmation is closed, while
unrelated still-current entries and owner-returned resolved history remain.
When every actionable record has elapsed the list becomes stale until a
fresh owner read. No browser expiration is converted into a server status,
permit or command receipt. In-flight commands keep their own exact-source
reconciliation lifecycle rather than being aborted solely because another
listed record's deadline elapsed.
The exact-session inspector uses the same guard for Project access and for
an active session's own expiry. When the latter elapses, the snapshot is
hidden as stale; only a fresh owner read can display the current terminal
state. This local deadline never writes an expired/revoked status to the owner.


The main OIDC controller owns logout from both verified and identity-only views.
A child requests that operation rather than racing a separate POST against the
parent's membership read. The controller hides prior state immediately, cancels
older reads and records only the current logout result. Standalone identity
widgets retain their own logout behavior without refreshing over an in-flight
logout. `tests/fixtures/proof-lifetime.entry.ts` is an isolated component-only
acceptance entry; it adds no application route or authentication provider.

Before a Project command, the UI now reads the source-backed
`GET /api/v1/auth/me?project_uuid=<canonical UUIDv4>` contract, verifying one
exact returned Project and at most its owner Team. The ordinary `/me` remains
navigation inventory only. No fallback to an inventory scan, another Project
or client-inferred membership is used on denied/unavailable point reads.

The Project scope selector can request an exact known Project even when it is
absent from the capped navigation inventory. A point proof is shown separately,
never merged into the inventory. The selected scope survives view changes and
proof renewal; command checks remain bound to that same Project. Switching
unmounts old action widgets before the owner lookup. A denied point lookup does
not silently choose another Project. Returning to the inventory cancels a
pending lookup and rejects its late response. Logout or a different Rauthy
issuer/subject/client clears the scoped selection, including after an outage.
