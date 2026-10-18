"""Clean local prototype schema; requires an empty owner database."""

from __future__ import annotations

from alembic import op

revision = "platform_20261018_0001"
down_revision = None
branch_labels = None
depends_on = None
source_signature = "d73c73e7a0a1ccf5fd175b10fe10d5f13751dd325a7d04671f8629988b8d644e"

_DDL: tuple[str, ...] = (
    ('CREATE SCHEMA "agents"'),
    ('CREATE SCHEMA "control"'),
    ('CREATE SCHEMA "projects"'),
    ('CREATE SCHEMA "teams"'),
    (
        "CREATE TABLE control.audit (\n\tid UUID NOT NULL, \n\toperation_"
        "uuid UUID NOT NULL, \n\tactor_user_id UUID, \n\tproject_id UUID,"
        " \n\taction VARCHAR(128) NOT NULL, \n\tobject_id VARCHAR(128) NO"
        "T NULL, \n\towner_revision VARCHAR(128) NOT NULL, \n\tdetails JS"
        "ONB NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL"
        ", \n\tPRIMARY KEY (id)\n)"
    ),
    ("CREATE INDEX ix_platform_audit_actor_time ON control.audit (actor_user_id, created_at)"),
    (
        "CREATE TABLE control.commands (\n\tid UUID NOT NULL, \n\toperati"
        "on_uuid UUID NOT NULL, \n\tactor_scope VARCHAR(64) NOT NULL, \n"
        "\tproject_scope VARCHAR(64) NOT NULL, \n\toperation VARCHAR(128"
        ") NOT NULL, \n\tkey VARCHAR(128) NOT NULL, \n\tfingerprint VARCH"
        "AR(64) NOT NULL, \n\texpected_owner_revision VARCHAR(128) NOT "
        "NULL, \n\tstate VARCHAR(16) NOT NULL, \n\tencrypted_outcome TEXT"
        ", \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tupdated_"
        "at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIMESTAMP"
        " WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT c"
        "k_platform_command_state CHECK (state IN ('pending','complet"
        "ed','unknown','reconciled','denied')), \n\tCONSTRAINT uq_platf"
        "orm_command_key UNIQUE (actor_scope, project_scope, operatio"
        "n, key), \n\tCONSTRAINT uq_platform_command_uuid_phase UNIQUE "
        "(operation_uuid, operation)\n)"
    ),
    ("CREATE INDEX ix_platform_command_reconcile ON control.commands (state, updated_at)"),
    (
        "CREATE TABLE control.outbox (\n\tid UUID NOT NULL, \n\toperation"
        "_uuid UUID NOT NULL, \n\tevent_name VARCHAR(128) NOT NULL, \n\to"
        "wner_revision VARCHAR(128) NOT NULL, \n\tevent_payload JSONB N"
        "OT NULL, \n\tattempts INTEGER NOT NULL, \n\tdelivery_claim_uuid "
        "UUID, \n\tavailable_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\tcl"
        "aimed_until TIMESTAMP WITH TIME ZONE, \n\tdelivered_at TIMESTA"
        "MP WITH TIME ZONE, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT"
        " NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_platform_outbox_e"
        "ffect UNIQUE (operation_uuid, event_name)\n)"
    ),
    ("CREATE INDEX ix_platform_outbox_pending ON control.outbox (delivered_at, available_at)"),
    (
        "CREATE TABLE control.rauthy_user_links (\n\tuser_id UUID NOT N"
        "ULL, \n\tissuer VARCHAR(512) NOT NULL, \n\tsubject VARCHAR(256) "
        "NOT NULL, \n\tbriareus_role VARCHAR(16) NOT NULL, \n\tactive BOO"
        "LEAN NOT NULL, \n\tversion INTEGER NOT NULL, \n\tcreated_at TIME"
        "STAMP WITH TIME ZONE NOT NULL, \n\tupdated_at TIMESTAMP WITH T"
        "IME ZONE NOT NULL, \n\tPRIMARY KEY (user_id), \n\tCONSTRAINT uq_"
        "rauthy_user_subject UNIQUE (issuer, subject), \n\tCONSTRAINT c"
        "k_rauthy_user_link_role CHECK (briareus_role IN ('user','ope"
        "rator')), \n\tCONSTRAINT ck_rauthy_user_link_version CHECK (ve"
        "rsion >= 1)\n)"
    ),
    (
        "CREATE TABLE control.scope_cursors (\n\tscope_kind VARCHAR(16)"
        " NOT NULL, \n\tscope_id UUID NOT NULL, \n\tepoch UUID NOT NULL, "
        "\n\trevision BIGINT NOT NULL, \n\tupdated_at TIMESTAMP WITH TIME"
        " ZONE NOT NULL, \n\tPRIMARY KEY (scope_kind, scope_id), \n\tCONS"
        "TRAINT ck_scope_cursor_kind CHECK (scope_kind IN ('user','te"
        "am','project')), \n\tCONSTRAINT ck_scope_cursor_revision CHECK"
        " (revision >= 0)\n)"
    ),
    (
        "CREATE TABLE control.scope_delivery_receipts (\n\tid UUID NOT "
        "NULL, \n\tsubscriber_id UUID NOT NULL, \n\tscope_kind VARCHAR(16"
        ") NOT NULL, \n\tscope_id UUID NOT NULL, \n\tepoch UUID NOT NULL,"
        " \n\tack_sequence BIGINT NOT NULL, \n\tupdated_at TIMESTAMP WITH"
        " TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_sco"
        "pe_subscriber_cursor UNIQUE (subscriber_id, scope_kind, scop"
        "e_id), \n\tCONSTRAINT ck_scope_ack_revision CHECK (ack_sequenc"
        "e >= 0)\n)"
    ),
    (
        "CREATE TABLE control.scope_events (\n\tevent_id UUID NOT NULL,"
        " \n\tscope_kind VARCHAR(16) NOT NULL, \n\tscope_id UUID NOT NULL"
        ", \n\tsequence BIGINT NOT NULL, \n\tepoch UUID NOT NULL, \n\tsourc"
        "e_outbox_id UUID NOT NULL, \n\tevent_type VARCHAR(128) NOT NUL"
        "L, \n\tactor_user_id UUID, \n\tsafe_payload JSONB NOT NULL, \n\tcr"
        "eated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\texpires_at TIM"
        "ESTAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (event_id), \n\t"
        "CONSTRAINT ck_scope_event_kind CHECK (scope_kind IN ('user',"
        "'team','project')), \n\tCONSTRAINT ck_scope_event_sequence CHE"
        "CK (sequence >= 1), \n\tCONSTRAINT uq_scope_event_sequence UNI"
        "QUE (scope_kind, scope_id, sequence), \n\tCONSTRAINT uq_scope_"
        "outbox_ingest UNIQUE (scope_kind, scope_id, source_outbox_id"
        ")\n)"
    ),
    (
        "CREATE INDEX ix_scope_event_delivery ON control.scope_events"
        " (scope_kind, scope_id, sequence)"
    ),
    ("CREATE INDEX ix_scope_event_retention ON control.scope_events (expires_at)"),
    (
        "CREATE TABLE teams.teams (\n\tid UUID NOT NULL, \n\tname VARCHAR"
        "(255) NOT NULL, \n\towner_user_id UUID NOT NULL, \n\tresource_re"
        "vision INTEGER NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZO"
        "NE NOT NULL, \n\tPRIMARY KEY (id)\n)"
    ),
    ("CREATE INDEX ix_teams_teams_owner_user_id ON teams.teams (owner_user_id)"),
    (
        "CREATE TABLE projects.projects (\n\tid UUID NOT NULL, \n\tname V"
        "ARCHAR(255) NOT NULL, \n\tlifecycle_status VARCHAR(12) DEFAULT"
        " 'active' NOT NULL, \n\towner_user_id UUID, \n\towner_team_id UU"
        "ID, \n\tresource_revision INTEGER NOT NULL, \n\tcreated_at TIMES"
        "TAMP WITH TIME ZONE NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAI"
        "NT ck_project_exclusive_owner CHECK ((owner_user_id IS NOT N"
        "ULL) <> (owner_team_id IS NOT NULL)), \n\tCONSTRAINT ck_projec"
        "t_lifecycle_status CHECK (lifecycle_status IN ('active','del"
        "eting','deleted')), \n\tFOREIGN KEY(owner_team_id) REFERENCES "
        "teams.teams (id) ON DELETE RESTRICT\n)"
    ),
    ("CREATE INDEX ix_project_owner_team ON projects.projects (owner_team_id)"),
    ("CREATE INDEX ix_project_owner_user ON projects.projects (owner_user_id)"),
    (
        "CREATE TABLE teams.memberships (\n\tid UUID NOT NULL, \n\tteam_i"
        "d UUID NOT NULL, \n\tuser_id UUID NOT NULL, \n\tactive BOOLEAN N"
        "OT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_team_membership"
        "_user UNIQUE (team_id, user_id), \n\tFOREIGN KEY(team_id) REFE"
        "RENCES teams.teams (id) ON DELETE CASCADE\n)"
    ),
    ("CREATE INDEX ix_membership_user_active ON teams.memberships (user_id, active)"),
    ("CREATE INDEX ix_teams_memberships_team_id ON teams.memberships (team_id)"),
    (
        "CREATE TABLE agents.identities (\n\tid UUID NOT NULL, \n\tprojec"
        "t_id UUID NOT NULL, \n\tparent_agent_id UUID, \n\tname VARCHAR(2"
        "55) NOT NULL, \n\tenabled BOOLEAN NOT NULL, \n\tversion INTEGER "
        "NOT NULL, \n\tcreated_at TIMESTAMP WITH TIME ZONE NOT NULL, \n\t"
        "PRIMARY KEY (id), \n\tCONSTRAINT uq_agent_project_identity UNI"
        "QUE (id, project_id), \n\tCONSTRAINT fk_agent_parent_same_proj"
        "ect FOREIGN KEY(parent_agent_id, project_id) REFERENCES agen"
        "ts.identities (id, project_id), \n\tFOREIGN KEY(project_id) RE"
        "FERENCES projects.projects (id) ON DELETE RESTRICT\n)"
    ),
    ("CREATE INDEX ix_agent_project_enabled ON agents.identities (project_id, enabled)"),
)


def upgrade() -> None:
    for statement in _DDL:
        op.get_bind().exec_driver_sql(statement)


def downgrade() -> None:
    raise RuntimeError("Clean prototype databases must be recreated explicitly")
