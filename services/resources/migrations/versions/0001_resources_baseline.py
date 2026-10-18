"""Clean local prototype schema; requires an empty owner database."""

from __future__ import annotations

from alembic import op

revision = "resources_20261018_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "8d90e38d55364e7c9d5622ff2063ff82687e73ab72015313933a912293a9d1c3"

_DDL: tuple[str, ...] = (
    ('CREATE SCHEMA "resources"'),
    (
        "CREATE TABLE resources.audit (\n\tid UUID NOT NULL, \n\toperatio"
        "n_uuid UUID NOT NULL, \n\tactor_user_id UUID, \n\tproject_id UUI"
        "D, \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) "
        "NOT NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tdetails "
        "JSONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NU"
        "LL, \n\tPRIMARY KEY (id)\n)"
    ),
    ("CREATE INDEX ix_resources_audit_actor_time ON resources.audit (actor_user_id, created_at)"),
    (
        "CREATE TABLE resources.commands (\n\tid UUID NOT NULL, \n\topera"
        "tion_uuid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL,"
        " \n\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(1"
        "28) NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VAR"
        "CHAR(64) NOT NULL, \n\texpected_owner_revision VARCHAR(128) NO"
        "T NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tencrypted_outcome TE"
        "XT, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdate"
        "d_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTA"
        "MP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT"
        " ck_resources_command_state CHECK (state IN ('pending','comp"
        "leted','unknown','reconciled','denied')), \n\tCONSTRAINT uq_re"
        "sources_command_key UNIQUE (actor_scope, project_scope, oper"
        "ation, key), \n\tCONSTRAINT uq_resources_command_uuid_phase UN"
        "IQUE (operation_uuid, operation)\n)"
    ),
    ("CREATE INDEX ix_resources_command_reconcile ON resources.commands (state, updated_at)"),
    (
        "CREATE TABLE resources.credential_leases (\n\tid UUID NOT NULL"
        ", \n\tproject_id UUID NOT NULL, \n\tuser_id UUID NOT NULL, \n\tses"
        "sion_uuid UUID NOT NULL, \n\tresource_id UUID NOT NULL, \n\tkind"
        " VARCHAR(16) NOT NULL, \n\towner_scope VARCHAR(16) NOT NULL, \n"
        "\towner_id UUID NOT NULL, \n\tresource_version INTEGER NOT NULL"
        ", \n\tservice_id UUID, \n\tservice_instance_uuid UUID, \n\toperati"
        "on_uuid UUID, \n\tservice_audience VARCHAR(64), \n\tcorrelation_"
        "id UUID, \n\tproject_state_hash VARCHAR(64) NOT NULL, \n\tprojec"
        "t_resource_revision INTEGER NOT NULL, \n\tteam_state_hash VARC"
        "HAR(64), \n\tteam_resource_revision INTEGER, \n\tsession_version"
        " INTEGER NOT NULL, \n\texpires_at TIMESTAMP WITH TIME ZONE NOT"
        " NULL, \n\tredeemed_at TIMESTAMP WITH TIME ZONE, \n\tPRIMARY KEY"
        " (id), \n\tCONSTRAINT ck_lease_resource_kind CHECK (kind IN ('"
        "integration','variable')), \n\tCONSTRAINT ck_lease_service_ope"
        "ration_owner CHECK ((service_id IS NULL AND service_instance"
        "_uuid IS NULL AND operation_uuid IS NULL) OR (service_id IS "
        "NOT NULL AND service_instance_uuid IS NOT NULL AND operation"
        "_uuid IS NOT NULL)), \n\tCONSTRAINT uq_credential_service_oper"
        "ation UNIQUE (project_id, service_id, service_instance_uuid,"
        " operation_uuid)\n)"
    ),
    ("CREATE INDEX ix_credential_lease_expiry ON resources.credential_leases (expires_at)"),
    (
        "CREATE TABLE resources.integrations (\n\tid UUID NOT NULL, \n\ta"
        "lias VARCHAR(128) NOT NULL, \n\talias_key VARCHAR(128) NOT NUL"
        "L, \n\tprovider VARCHAR(32) NOT NULL, \n\tauth_type VARCHAR(32) "
        "NOT NULL, \n\tprovider_settings JSONB NOT NULL, \n\tencrypted_cr"
        "edential TEXT NOT NULL, \n\tversion INTEGER NOT NULL, \n\tcreate"
        "d_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTA"
        "MP WITH TIME ZONE NOT NULL, \n\tdeleted_at TIMESTAMP WITH TIME"
        " ZONE, \n\towner_team_id UUID, \n\towner_project_id UUID, \n\tPRIM"
        "ARY KEY (id), \n\tCONSTRAINT ck_integration_owner_xor CHECK (("
        "owner_team_id IS NOT NULL) <> (owner_project_id IS NOT NULL)"
        ")\n)"
    ),
    ("CREATE INDEX ix_integration_provider ON resources.integrations (provider, auth_type)"),
    (
        "CREATE UNIQUE INDEX uq_integration_project_alias ON resource"
        "s.integrations (owner_project_id, alias_key) WHERE owner_pro"
        "ject_id IS NOT NULL AND deleted_at IS NULL"
    ),
    (
        "CREATE UNIQUE INDEX uq_integration_team_alias ON resources.i"
        "ntegrations (owner_team_id, alias_key) WHERE owner_team_id I"
        "S NOT NULL AND deleted_at IS NULL"
    ),
    (
        "CREATE TABLE resources.outbox (\n\tid UUID NOT NULL, \n\toperati"
        "on_uuid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n"
        "\towner_revision VARCHAR(128) NOT NULL, \n\tevent_payload JSONB"
        " NOT NULL, \n\tattempts INTEGER NOT NULL, \n\tdelivery_claim_uui"
        "d UUID, \n\tavailable_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\t"
        "claimed_until TIMESTAMP WITH TIME ZONE, \n\tdelivered_at TIMES"
        "TAMP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE N"
        "OT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_resources_outbo"
        "x_effect UNIQUE (operation_uuid, event_name)\n)"
    ),
    ("CREATE INDEX ix_resources_outbox_pending ON resources.outbox (delivered_at, available_at)"),
    (
        "CREATE TABLE resources.variables (\n\tid UUID NOT NULL, \n\tname"
        "_key VARCHAR(128) NOT NULL, \n\tplain_value TEXT, \n\tencrypted_"
        "value TEXT, \n\tis_secret BOOLEAN NOT NULL, \n\tversion INTEGER "
        "NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\t"
        "updated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tdeleted_at T"
        "IMESTAMP WITH TIME ZONE, \n\towner_team_id UUID, \n\towner_proje"
        "ct_id UUID, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_variable_own"
        "er_xor CHECK ((owner_team_id IS NOT NULL) <> (owner_project_"
        "id IS NOT NULL)), \n\tCONSTRAINT ck_variable_secret_storage CH"
        "ECK ((is_secret AND encrypted_value IS NOT NULL AND plain_va"
        "lue IS NULL) OR (NOT is_secret AND encrypted_value IS NULL A"
        "ND plain_value IS NOT NULL))\n)"
    ),
    (
        "CREATE UNIQUE INDEX uq_variable_project_key ON resources.var"
        "iables (owner_project_id, name_key) WHERE owner_project_id I"
        "S NOT NULL AND deleted_at IS NULL"
    ),
    (
        "CREATE UNIQUE INDEX uq_variable_team_key ON resources.variab"
        "les (owner_team_id, name_key) WHERE owner_team_id IS NOT NUL"
        "L AND deleted_at IS NULL"
    ),
    (
        "CREATE TABLE resources.external_operations (\n\tid UUID NOT NU"
        "LL, \n\tactor_id UUID NOT NULL, \n\tproject_id UUID NOT NULL, \n\t"
        "session_uuid UUID NOT NULL, \n\tresource_id UUID NOT NULL, \n\tr"
        "esource_version INTEGER NOT NULL, \n\tservice_id UUID NOT NULL"
        ", \n\tinstance_uuid UUID NOT NULL, \n\toperation_uuid UUID NOT N"
        "ULL, \n\toperation VARCHAR(128) NOT NULL, \n\tidempotency_digest"
        " VARCHAR(64) NOT NULL, \n\trequest_fingerprint VARCHAR(64) NOT"
        " NULL, \n\tresult_sha256 VARCHAR(64), \n\tstatus VARCHAR(16) NOT"
        " NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tdis"
        "patched_at TIMESTAMP WITH TIME ZONE, \n\tresolved_at TIMESTAMP"
        " WITH TIME ZONE, \n\tPRIMARY KEY (id), \n\tCONSTRAINT ck_externa"
        "l_operation_status CHECK (status IN ('reserved', 'dispatched"
        "', 'succeeded', 'unknown')), \n\tCONSTRAINT uq_external_operat"
        "ion_identity UNIQUE (actor_id, project_id, operation, idempo"
        "tency_digest), \n\tCONSTRAINT uq_external_service_operation UN"
        "IQUE (project_id, service_id, instance_uuid, operation_uuid)"
        ", \n\tFOREIGN KEY(resource_id) REFERENCES resources.integratio"
        "ns (id) ON DELETE RESTRICT\n)"
    ),
    ("CREATE INDEX ix_external_unknown ON resources.external_operations (status, created_at)"),
    (
        "CREATE UNIQUE INDEX uq_external_uncertain_effect ON resource"
        "s.external_operations (project_id, resource_id, operation, r"
        "equest_fingerprint) WHERE status IN ('dispatched','unknown')"
    ),
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("Clean prototype databases must be recreated explicitly")
