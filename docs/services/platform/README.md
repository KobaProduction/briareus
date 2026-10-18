# Briareus Platform Control — service-local runtime

**Owner:** Backend, approved Briareus MCP Development Application. This
service is independent from Gateway, Control Panel UI/API and External Services.

- Source: `services/platform/src/` (canonical owner packages).
- Service migrations: **one clean reviewed current-schema baseline**
  `platform_20261018_0001`, generated from the complete current Platform
  SQLAlchemy metadata (Teams, Projects, Users link, agents, audits, scope
  events and ledgers). Historical platform_0001→0004 is RETIRED from the
  candidate source. This new epoch requires a genuinely EMPTY
  `briareus_platform` logical database before first owner startup.
  Existing Alembic revisions are not accepted, migrated or stamped.
- Runtime: Python 3.13, frozen `uv.lock`, `uv run --frozen --no-sync`,
  container `briareus-platform` and DNS alias of the same name, internal port
  8000. Health probe `GET /health/live`, not proof of business authorization.
- Database: existing `briareus_platform` in existing `briareus-postgres` server
  on `briareus-net`. There is **no new database server, named volume, SQL
  role, public HTTP domain or independent database migration sidecar**.
- Application only receives existing `{{environment.POSTGRES_USER}}`,
  `{{environment.POSTGRES_PASSWORD}}` and telemetry / timezone Shared
  references. Never copy or reveal actual Shared secret values.

## Shared dependency review

`Projects, Teams, Agents and their lifecycle` are owned in this service folder. Both Platform and Catalog still
import a bounded subset of transitional `services/common/*.py` through the
`common` Python import root. This is one shared source of truth; **do not copy
the common package into each service's Git source** or move the authority of
another running Backend/Authorization owner in this cutover.

The Compose Watch paths are exactly:

- `services/platform/**` — service source, uv dependencies, Compose and migrations
- `services/common/**` — temporarily imported shared Python contracts/runtime
- `shared/build/**` — single shared build provenance utility
- `services/external/**` — shared External runtime dependency

The service Dockerfile copies only its own local code plus explicitly selected
shared/common source files and one `shared/build/runtime_write_provenance.py`
utility. The accepted next refactor may promote narrow common DTOs to
`shared/contracts/` after all consumers are reconciled; until then, keep the
transitional import paths and Watch dependencies honest.

## Existing Coolify resource cutover and acceptance

Retain the **same approved** Coolify UUID (no new Application). Repo
`KobaProduction/briareus`, branch `main`.

- Base Directory: `/services/platform`
- Docker Compose location: `/docker-compose.coolify.yaml`
- Watch Paths: the four paths above, in the same order
- Deployment is Git-backed, not a UI-only Compose replacement.
- Existing secret references, domain (none), networking and DB identity are
  unchanged. The old `deploy/platform/` source remains for rollback until the
  new runtime is independently accepted.

Verification requires: reviewed Git commit/green required CI; Coolify saved
Base/Compose/Watch and same-revision deployment; private container health;
owner database Alembic head (non-mutating observation), and a real relevant
private owner API response. Business permission/OAuth acceptance is independent
from container health. If cutover fails, restore the recorded prior
`/deploy/platform` Base and legacy Compose/Watch values and redeploy only
this application without deleting data.

## Closed Rauthy User mapping (local-first source; no Dev deployment)

The Platform service owns a stable external
`(Rauthy issuer, Rauthy sub) → Briareus User UUIDv4` binding. It does not
store IdP passwords, issue JWTs, allow public signup, inherit Rauthy Groups
as Project membership or silently create users during OAuth callback.

The proposed owner-local `control.rauthy_user_links` table records
`user_id`, `issuer`, `subject`, independently assigned `briareus_role`
(user/operator), `active`, `version` and audit timestamps. Unique issuer+
subject and unique User ID prohibit accidental multiple links; no foreign
key points into another owner's logical database.

An operator may establish a link only through
`PlatformRauthyEnrollmentService` after independently authenticated
`TrustedOperatorEnrollmentPort` approval and a fresh server-side Rauthy
Users:read status. Creating an operator account additionally requires
separate operator-assignment privilege and must not be self-approved.
The owner transaction creates one row plus native Platform audit/outbox
without persisting a provider credential or access token. A repeat of the
same exact link is no-op; conflicting reassignment is forbidden.

`PlatformCurrentSubjectLinkReader` reads the own DB row and demands a
fresh ≤30s Rauthy status before returning any active User link. This feeds
`PlatformOidcMembershipProjection`, which uses **only** active Team/Project
owner rows from `briareus_platform`, with ordinary active members able to
use resources but not approve elevated AgentSessions. Actual Rauthy
session identity and current operator status must be established from
real trusted upstream/owner ports, not caller headers or supplied UUID.

**Owner-approved experimental greenfield rebaseline:** The prior legacy
Platform 0001→0004 chain has been removed from the new source tree; all the
current Team/Project lifecycle, phased command-idempotency, Rauthy User-link
and scoped owner tables are part of ONE reviewed `platform_20261018_0001`
revision. The baseline DDL comes directly from the current Platform ORM,
not a hand-edited partial bootstrap. A unique epoch/version ID prevents a
previous Development Alembic 0001/0003/0004 row from masquerading as current.
The coordinator rejects all prior versions and any nonempty unversioned
schema or pre-existing Platform namespace before executing fresh DDL.

The source-local and historical scripts/alembic_owners Platform wheel-input
copies of the single fresh migration are kept byte-identical and source-hash
pinned. The old revisions remain recoverable from Git history for forensic
review or rollback, but are NOT accepted as an upgrade path in this new
experimental Development epoch. Default provider-facing operation does not
perform any schema reset on its own.

A reset must target ONLY the independently confirmed `briareus_platform`
logical owner DB through Deployment's exact allowlisted Development scope,
not the shared PostgreSQL PGDATA volume, external provider database,
existing Rauthy root/admin users or OAuth keys, Files storage directories or
root mounts. The existing Platform User/Team/Project mappings WILL be lost
by the intentional reset. External Rauthy users will still exist but require
NEW approved trusted Platform enrollment/first-operator bootstrap; no
automatic User or operator is reconstructed from an arbitrary Rauthy group.
Dependent Access/Catalog UI features remain unavailable until current owner
proofs are genuinely rebuilt. Authorization's own database, if separately
reset, must use its own reviewed new epoch.

**Acceptance boundary:** SOURCE migration graph, current compiled ORM DDL,
revision uniqueness and fail-closed old-state checks are tested locally.
This does NOT establish that the actual Development database was reset or
newly migrated. Deployment owns a verified disposable PostgreSQL rehearsal,
precise service stop/restart order, qualified per-database reset with recovery
information and read-only final `alembic_version`/owner schema verification.
No live Rauthy data, Dev database, roots or volumes were changed by Backend.

The separate `PlatformRauthySuspensionService` requires a new, signed,
short-lived operator suspension proof tied to the exact existing User ID and
expected current link version. It locks the Platform row, sets `active=false`,
increments revision and emits own audit/outbox records atomically. Repeating a
stale operation conflicts; a deactivated link is denied by each new
`/api/v1/auth/me` owner resolution even when a Rauthy session has not yet
expired. General Users permission cannot suspend a Platform operator, for
which last-operator recovery requires an independent reviewed contract.
This remains source-only until authenticated owner transport and the reviewed
additive schema exist in approved Development.

## Private OIDC current-user source API (LOCAL only)

`projects.control_runtime:create_platform_app` mounts
`POST /internal/v1/platform/oidc/current` under the Platform service itself.
The request body `{issuer:string,subject:string,project_uuid?:UUIDv4}` is **only a selector**,
not proof of authentication. The source requires an explicitly injected
`TrustedPanelContextAttestor` returning a recent signed and authenticated
`VerifiedPanelContextPeer` bound to the exact issuer+subject and optional
Project selector, audience
`briareus:platform` and `control-panel-api` consumer. Browser cookies
are forbidden on this private route; no public Platform issuer/JWT exists.

After attestation, only the owner-local Platform source projects an existing
active Rauthy→User binding and its current Team/Project memberships into
`{issuer,subject,user_uuid,enabled,role,expires_at,teams,projects}`.
There is no role inference from supplied request strings or upstream groups.
Private route errors: 401 absent service proof, 403 unlinked/unprivileged
subject, 503 unconfigured attestor/owner source or unavailable data. The
default `create_platform_app()` supplies NONE of these trusted ports and
therefore responds 503 even when the service health is green.

The Panel BFF separately implements `PrivatePlatformCurrentClient`, which
requires an independently attested mTLS/Unix transport and a short-lived
signed subject delegation, validates exact response shape/subject/expiry
and only then exposes the public cookie-bound `/api/v1/auth/me`.
These are LOCAL source contracts. A two-app in-memory ASGI probe confirms
the cookie→private-Platform→public DTO chain with injected synthetic
attestors, **not** real network mTLS, Rauthy login, PostgreSQL membership,
operator provisioning or Dev acceptance.

## Greenfield first Platform operator: explicit one-time trust gate

An empty Platform database has no Briareus operator, so ordinary operator-only
enrollment cannot create the first one. The Platform-local
projects._rauthy_first_operator.FirstOperatorBootstrap provides a private
out-of-band first-operator workflow for an EXISTING Rauthy admin account only
after independent signed operator authority, fixed audience, exact Rauthy
issuer/subject and a fresh server-side Users:read status are verified.
No Rauthy OAuth ID-token group or email automatically issues operator rights.
The bootstrap handler also enforces the same exact pinned public Rauthy issuer
as the Platform Users:read adapter (or the separately configured disposable
localhost:18444 sandbox issuer). The subject must be exactly the provider's
24-character ASCII-alphanumeric immutable User ID. A foreign signed issuer,
invalid subject or untrusted local endpoint is denied BEFORE any privileged
Users:read request or Platform SQL transaction. The issuer is never selected
from a browser-supplied URL, User email or Rauthy Group.

The independently signed one-time first-operator approval additionally
names a NEW UUIDv4 personal Project and a bounded canonical Project name.
This solves the otherwise fatal greenfield MVP gap where the first valid
Rauthy-backed operator exists but has NO Project for a real AgentSession.
It is NOT an automatic OAuth/IdP-group Project grant: the initial Project
is approved as part of the same independently verified bootstrap evidence
and belongs exclusively to that operator User (owner_team_id=NULL,
status=active, version=1, resource_revision=0).

The owner transaction acquires a PostgreSQL advisory transaction lock
BEFORE checking the absence of every User link, then inserts the first
Rauthy→User operator link AND its approved personal Project, two separate
audit records and two outbox events ATOMICALLY in briareus_platform.
This protects the empty-table race under READ COMMITTED and prevents
an orphaned first operator who cannot own any Project. The same transaction
now checks **all current Platform-owned ORM tables**, not only the User link,
Project and Team tables: retained audit/outbox, prior Agent identities,
commands or realtime scope records after a partially cleared Development
schema DENY initial trust creation. This does not silently repair leftover
rows or delete any owner data. A subsequent or disabled User link permanently
blocks this special bootstrap; operator recovery requires an independent
reviewed proof and cannot reuse this path.

A second proof-expiry check runs AFTER awaited SQL transaction completion.
If the independent first-operator approval or Rauthy User-status evidence
expires while commit is finishing, the request returns unavailable rather
than falsely acknowledging a current operator grant. The write **may already
have committed**; the consumer must reconcile through a fresh trusted owner
read and must not blindly retry with a newly invented operator identity.
This does not claim distributed atomicity across Rauthy and PostgreSQL.

There is NO public bootstrap HTTP endpoint, hardcoded admin, generated password,
weak environment switch, or automatic auth fallback. Source-level local tests
used synthetic independently verified proofs and assert first User+Project
creation, source-projected current Project use_resources/approve_agent_session,
two audit/outbox events, negative replay and unapproved-origin rejection.
They do NOT establish a real provider login, actual PostgreSQL atomic commit,
mTLS attestor/Users:read or Dev acceptance.

**Physical source-only greenfield proof (2026-10-15):** using native disposable
PostgreSQL 18.6 logical databases and the actual current owner Alembic code,
a separately mocked signed first-operator authority and mocked Users:read
active status were injected into the real Platform service. It denied
unsigned approval, denied retained synthetic control.audit data despite
empty User/Team/Project, then created exactly one User-link, one personal
Project, two audit and two outbox rows. It denied a second bootstrap and
resolved the resulting Project through real owner SQL with use_resources and
approve_agent_session. A paired separate Access owner DB then used the
actual Rauthy-actor-bound Access command/SQL transaction and Cedar evaluator
to open a normal AgentSession once (idempotent replay), allow only baseline
Project mcp.connect/files.read, deny files.write and foreign Project, and
deny every formerly permitted operation after revoke. The two owner DBs
remained separate; no cross-owner FK, shared transaction or mocked Permit
was inserted. Results: local/backend-greenfield-20261015/
native-first-operator-result.json and native-platform-access-result.json.
Both temporary PGDATA directories were removed on process exit. Because
signing and Rauthy Users:read were synthetic, this proves **Backend SQL and
Cedar integration only**, not authenticated Dev onboarding or a real signed
Hand-to-Access Files effect.

## Private Authorization Project membership lookup

The Platform owner's local private route
POST /internal/v1/platform/oidc/project-member exists separately from
the Control Panel /current route. The Authorization service must present
an independently verified private service identity, Rauthy issuer/subject
delegation and Project UUID. The owner returns a short-lived binding to
the actual Platform User only when the current Rauthy User is enabled and
that Project is active and accessible through personal or active Team
membership. Unknown or suspended users and unrelated Project IDs deny.
The caller's bearer, request body and HTTP headers are not substitutes
for real trust; absent trust still returns 503 by default.

Local ASGI cross-owner source probes validated 200/403/503 using synthetic
verified peers; full Platform SQL and existing Rauthy sign-in were not run.

## Exact Project membership without inventory enumeration

`PlatformOidcMembershipProjection.resolve_project(issuer, subject, project_uuid)`
checks a single active Project using one owner-local SQL SELECT joining that
Project's Team and the current actor's active Team membership. It independently
resolves the current enabled Rauthy-to-User link first. No unrelated Team or
Project is enumerated, and the inventory's 100-item safety cap cannot deny a
valid exact Project lookup. Personal ownership and Team ownership are exclusive;
a current Team member may use resources but only the current Team owner receives
approval capability. An unknown, deleted, inaccessible or inactive Project denies.
The original User-link expiry must still hold after transaction exit.

Private `/project-member` always uses the exact lookup. Private `/current` uses it
when the optional Project selector is present; otherwise its existing bounded
navigation inventory is unchanged. Its verified peer must bind the exact
Project (or None for inventory), not merely issuer/subject. The typed BFF peer
now provides `signed_project_delegation`; no fallback to a subject-only token
is permitted. Scoped output contains one matching Project and zero or one Team.
The UI and BFF receive no owner SQL handles and cannot supply User/role claims.

Focused local tests execute the actual SQLAlchemy joins against disposable
SQLite tables containing more than 100 memberships and compile the same SELECT
with PostgreSQL's dialect. They check owner/member/personal scope, current loss
of membership, deleted and foreign Projects, disabled Users and transaction-exit
expiry. The actual BFF and both private routers also run as distinct ASGI apps.
Issuer/User-link and peer attestations are explicit fixtures; SQLite proves
query behavior, not PostgreSQL isolation, genuine Rauthy enrollment or mTLS.

## Rauthy v0.37.1 — pinned current User status adapter

The source-only Platform owner can now compose
`platform_user_membership_with_rauthy(database, users_read_api_key)` from
`projects._rauthy_user_status` only after Deployment supplies an
independently scoped, server-held **Users:read** credential. This is not the
browser OAuth token, a default Admin key, or an automatic user bootstrap.
The key is never embedded in Git, copied to Frontend or logged.

The exact public upstream source was reviewed from
`sebadob/rauthy` tag `v0.37.1`, SHA
`ce35a70fbc43203b1a6910d3db30389228825f46`:
`src/api/src/users.rs` implements private `GET /users/{id}` with
`Users:read`; `src/api_types/src/users.rs::UserResponse` carries `id`,
`enabled`, optional Unix `user_expires`; ID-token and userinfo
`sub=user.id`; new Rauthy user IDs are 24 alphanumeric chars.
The Platform reader uses the fixed internal
`http://briareus-rauthy:8080/auth/v1/users/{id}` address (no caller host,
proxy or redirect), bounded JSON and a ten-second freshness proof. It
retains only the exact subject, active flag and short expiration (never
later than the upstream user_expires timestamp); no email, roles, groups,
passwords or other provider PII are projected to Briareus
grant authority. Missing/deleted (404), disabled or expired Users deny
membership, while a bad/read-only key, upstream outage or invalid reply
remains an explicit 503. Malformed, duplicate-key or mismatched ID JSON
never opens access.

Synthetic response decoding and isolated Platform source-only image
imports passed; **no real Rauthy Users:read permission, live user lookup,
credential distribution or physical Dev PostgreSQL was verified**.
The default Platform service remains unconfigured/fail-closed until its
own owner-level trusted peer, database and scoped Rauthy reader exist.

## MVP-first Platform owner startup and current User source (source-validated)

Platform's independent FastAPI owner composition can now activate one
authenticated current Rauthy→User→Project projection at service lifespan.
A trusted launcher must inject a verified mTLS/Unix owner ingress and
independent Control Panel or Authorization subject-bound peer attestor.
An optional protected Rauthy Users:read SecretStr plus no alternate
membership object constructs the Platform-local source ONLY after the
owner's existing migration/ingress cycle has passed and its
briareus_platform Alembic schema was independently verified.
The helper opens its own Platform-only read pool; it never opens Access
or Identity SQL. Its pool closes on exit or startup error.

For both POST /internal/v1/platform/oidc/current and /project-member,
the projection is now dynamically resolved only while the trusted owner
lifespan is ACTIVE; an injected source does not become accessible before
owner startup or after shutdown. Missing ingress, attestor, provider
credential, owner DB or successful schema verification remains 503. The
owner attestation expires in <=30s and is rechecked after a potentially
slow membership/provider lookup, before any current User+Project
response. No Rauthy User, Team, Project or Operator is automatically
created or granted privileges by a valid ID token or service port.

LOCAL evidence: a bounded synthetic owner-lifespan test with approved
injectable source confirms 503 before verified startup, valid 200 for
source-resolved Rauthy User during service lifetime and 503 after the
Platform-only pool closes. Delayed fake Platform membership lookups
also deny both Control Panel and Authorization private callers when
their previously valid peer proof expires before the response.
This test does not substitute for signed real mTLS/Unix identities,
physical PostgreSQL owner schema, actual Users:read key privileges,
operator-enrolled Platform subject links or Development authentication.
The default released module still initializes with NO trusted ports and
returns 503. No new Postgres service or provider credentials are minted.

### First-operator independent proof expiry after SQL contention

The verified first-operator proof and current upstream Rauthy Users status
are short-lived. Holding an advisory lock and flushing the new User +
initial Project rows may take longer than either signed proof's TTL.
The bootstrap therefore checks BOTH expiry timestamps again immediately
before the owner transaction's commit boundary, after the inserts,
audit and outbox records are staged. If either expires, the whole
transaction aborts and cannot leave a new operator, orphaned Project
or partial audit/outbox. A local delayed-flush simulation deliberately
exhausted the 130ms signed owner proof and confirmed rollback rather
than first-operator success. This is source/transaction-control evidence,
not physical PostgreSQL atomicity or real Rauthy admin acceptance.

### Subsequent operator User enrollment and suspension: proof expiry fences

The first-operator bootstrap is not the only sensitive Platform User
mutation. After a separately authenticated current operator decision,
PlatformRauthyEnrollmentService.enroll locks or creates the Rauthy link
and stages audit/outbox within briareus_platform. Its short-lived
operator approval AND current upstream Rauthy User status must remain
valid after SQL lock/flush and immediately before transaction exit.
Expiration aborts the transaction instead of persisting a User with
stale permission.

PlatformRauthySuspensionService.suspend checks its separately signed
current operator authority both after waiting for the target User row
lock and before transaction completion. An expired proof may not change
the User active flag/version or persist audit/outbox. Operators still
require separate recovery authorization, not generic suspension.

Local fake-DB tests delayed enrollment flush and suspension lock past
signed proof TTL; both rejected and rolled back. Positive source tests
also confirmed current enrollment commits one User link + audit +
outbox, and current nonoperator suspension commits a disabled link +
new version + audit + outbox. SOURCE/LOCAL only, not physical PostgreSQL,
trusted Users:read key, current mTLS peer or Dev acceptance.

### First-operator bootstrap requires an actually empty Project owner

The one-time bootstrap already excludes an existing Rauthy User mapping.
In a partially recreated or incorrectly retained Platform database,
however, old Project rows might exist even if the Rauthy User-link table
is empty. Under the same Platform advisory transaction lock, source now
checks BOTH tables before allowing the first operator+personal Project
commit. A pre-existing Project without an Rauthy mapping is an explicit
cutover contradiction, not a reason to invent a new trust root beside
that Project. Bootstrap denies without adding any operator, Project,
audit or outbox records; never silently adopt orphaned legacy ownership.

Local transaction-controlled source probes pass the empty owner case
with one User+Project plus audit/outbox, reject repeated bootstrap, and
reject a nonempty Project database that has no Rauthy link. Actual
PostgreSQL/Dev schema ownership and any planned reset remain separate
deployment acceptance criteria.

### First-operator greenfield check also excludes retained Teams

An empty Rauthy User-link table and empty Project table do not prove the
Platform owner is greenfield when Teams from an interrupted legacy
cutover remain. The one-time first-operator transaction also verifies
that the Platform-own teams.teams table has NO existing rows while
holding the SAME advisory transaction lock, before inserting its
approved User and personal Project. Existing Team ownership is a
material contradiction requiring qualified Dev migration/recovery,
not an opportunity to create a parallel operator root.

Local existing source probe now separately verifies: empty owner
User+personal Project creation; replay denial; orphan Project denial;
and retained Team with no User or Project denial. Each denied path
does not insert an operator, Project or audit/outbox rows. This is
source/fake-SQL evidence, not proof that the real PostgreSQL owner is
empty or safe to reset. No fresh schema or secret is created by the
guard.

## Explicit disposable local Rauthy Users:read adapter (no Dev key needed)

The pinned source-only Platform User status reader now accepts a
TEST-ONLY local variant. The default path is unchanged: the fixed
private Development owner URL http://briareus-rauthy:8080/auth/v1/users/{id}
and exact issuer https://briareus.koba-nexus.ru/auth/v1/ with an
independently scoped protected Users:read key.

For LOCAL disposable testing, a trusted launcher may explicitly inject
a PEM certificate of the CURRENT localhost Rauthy listener using
test_only_local_rauthy_ca_pem when constructing create_platform_app,
together with a separately issued LOCAL Users:read SecretStr and
independently authenticated private ingress and operator/subject peer
attestor. This pins the LOCAL issuer to
https://localhost:18444/auth/v1/ and the private endpoint to exactly
https://localhost:18444/auth/v1/users/{24-character-sub}.
No user-supplied URL, proxy, redirect, runtime environment switch,
production issuer crossover or SSL verification bypass is permitted.
Certificate chain and localhost hostname are verified against the
supplied trusted local PEM. The trusted PEM contains ONLY public
certificate data; neither private TLS key nor Users:read credential
belongs in Git or logs. Without a real local scoped key/attestor,
the Platform owner API still fails closed 503.

REAL native local evidence: Rauthy OIDC discovery over TLS returned
200 after explicitly trusting the exact current disposable listener
certificate. Its private Users route returned HTTP401 with a knowingly
invalid LOCAL test key. This demonstrates working HTTP/TLS and correct
authorization denial, NOT an authorized Users:read 200 or membership.
Synthetic trusted local UserResponse (exact id, enabled, expiry)
returned a bounded active status without PII, while both local->Dev
and Dev->local issuer substitutions failed. The Platform factory
refused a disposable certificate without protected scoped key or
without an independently verified ingress. A genuine scoped LOCAL
Users:read key must be provisioned by the owner of the throwaway
Rauthy sandbox and supplied only by protected local reference;
real Project/Access/Cedar validation comes afterward.
