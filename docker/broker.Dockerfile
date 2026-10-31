# Broker image (Task 14). The only component with Graph credentials: profile
# certificates are mounted read-only at run time, never built in.
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv
RUN useradd --uid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin broker
WORKDIR /srv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY task_sdk ./task_sdk
COPY profiles ./profiles
COPY tasks ./tasks
COPY agent_profiles ./agent_profiles
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.11 && rm -rf /root/.cache
USER 10002:10002
EXPOSE 8080
CMD ["/srv/.venv/bin/uvicorn", "--factory", "clw.broker.app:create_production_app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
