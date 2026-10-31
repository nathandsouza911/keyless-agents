# Facade proxy image (SD-041). TLS for graph.microsoft.com inside script runs'
# network; forwards every request, undecided, to the broker. No credentials:
# its certificate and key are mounted at run time from the deployment's facade
# CA (clw facade-ca-init), never built in.
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv
RUN useradd --uid 10004 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin facade
WORKDIR /srv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY task_sdk ./task_sdk
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.11 && rm -rf /root/.cache
USER 10004:10004
EXPOSE 443
CMD ["/srv/.venv/bin/uvicorn", "--factory", "clw.facade_proxy.app:create_production_app", "--host", "0.0.0.0", \
     "--port", "443", "--ssl-certfile", "/run/secrets/facade/leaf.crt", "--ssl-keyfile", "/run/secrets/facade/leaf.key", \
     "--no-server-header", "--no-access-log"]
