# API image (Task 17C, A3). The public API: sign-in, task catalog, runs and
# tenant-scoped audit views. No Graph credentials, no profile certificates and
# no Docker socket: its database role can read and create runs, never start,
# end or redact them (clw.db.roles).
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv
RUN useradd --uid 10003 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin api
WORKDIR /srv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY task_sdk ./task_sdk
COPY profiles ./profiles
COPY tasks ./tasks
COPY agent_profiles ./agent_profiles
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.11 && rm -rf /root/.cache
USER 10003:10003
EXPOSE 8000
CMD ["/srv/.venv/bin/uvicorn", "--factory", "clw.api.main:create_production_app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-access-log"]
