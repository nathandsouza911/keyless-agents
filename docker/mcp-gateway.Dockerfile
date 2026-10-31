# MCP gateway image (SD-052): the endpoint AI agents connect to. No
# credentials, no profiles, no tasks: it talks only to the broker.
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv
RUN useradd --uid 10005 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway
WORKDIR /srv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY task_sdk ./task_sdk
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.11 && rm -rf /root/.cache
USER 10005:10005
EXPOSE 8090
CMD ["/srv/.venv/bin/uvicorn", "--factory", "clw.mcp_gateway.app:create_production_app", "--host", "0.0.0.0", \
     "--port", "8090", "--no-server-header", "--no-access-log"]
