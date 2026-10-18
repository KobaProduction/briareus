FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY services/platform/pyproject.toml /app/pyproject.toml
COPY services/platform/uv.lock /app/uv.lock
COPY services/platform/.python-version /app/.python-version
RUN --mount=type=cache,target=/root/.cache/uv,sharing=shared uv sync --frozen --no-dev --no-install-project
RUN useradd -u 1000 -m -d /home/briareus briareus \
    && install -d -m 0750 -o 1000 -g 1000 /run/briareus-platform /var/lib/briareus-platform
# Copy owner-local source and immutable owner migration history.
COPY services/platform/migrations/env.py /app/src/common/alembic_owners/platform/env.py
COPY services/platform/migrations/versions/0001_platform_baseline.py /app/src/common/alembic_owners/platform/versions/0001_platform_baseline.py
COPY services/platform/src/ /app/src/
# Historical services/common is shared by multiple owners; watch it explicitly.
COPY services/common/__init__.py /app/src/common/__init__.py
COPY services/common/account_contracts.py /app/src/common/account_contracts.py
COPY services/common/admin_api_client.py /app/src/common/admin_api_client.py
COPY services/common/cache.py /app/src/common/cache.py
COPY services/common/http_transport.py /app/src/common/http_transport.py
COPY services/common/models.py /app/src/common/models.py
COPY services/common/oauth_session_contracts.py /app/src/common/oauth_session_contracts.py
COPY services/common/observability.py /app/src/common/observability.py
COPY services/common/owner_bff_models.py /app/src/common/owner_bff_models.py
COPY services/common/owner_contracts.py /app/src/common/owner_contracts.py
COPY services/common/owner_effect_authorization.py /app/src/common/owner_effect_authorization.py
COPY services/common/owner_migrations.py /app/src/common/owner_migrations.py
COPY services/common/owner_proof_signing.py /app/src/common/owner_proof_signing.py
COPY services/common/owner_registry.py /app/src/common/owner_registry.py
COPY services/common/owner_runtime.py /app/src/common/owner_runtime.py
COPY services/common/owner_startup_diagnostics.py /app/src/common/owner_startup_diagnostics.py
COPY services/common/owner_team_contracts.py /app/src/common/owner_team_contracts.py
COPY services/common/owner_transactions.py /app/src/common/owner_transactions.py
COPY services/common/platform_db.py /app/src/common/platform_db.py
COPY services/common/platform_errors.py /app/src/common/platform_errors.py
COPY services/common/platform_ids.py /app/src/common/platform_ids.py
COPY services/common/platform_telemetry.py /app/src/common/platform_telemetry.py
COPY services/common/runtime_policy_contracts.py /app/src/common/runtime_policy_contracts.py
COPY services/common/settings.py /app/src/common/settings.py
# No installation of the Briareus project: source-only uv run.
COPY shared/build/runtime_write_provenance.py /app/runtime_write_provenance.py
RUN python /app/runtime_write_provenance.py platform
WORKDIR /app/src
USER 1000:1000
EXPOSE 8000
# Each service starts its OWN Alembic coordinator. Missing DB/grants fail closed.
CMD ["uv", "run", "--frozen", "--no-sync", "--no-dev", "--project", "/app", "--directory", "/app/src", "python", "-m", "projects.panel_server"]
