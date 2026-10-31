# Runner image (Task 14). Holds the Docker socket (mounted at run time) and
# database credentials; never Graph credentials or profile certificates.
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv
WORKDIR /srv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY task_sdk ./task_sdk
COPY profiles ./profiles
COPY tasks ./tasks
# The script-run bootstrap, to record its digest in RUN_STARTED (SD-044).
COPY task_pwsh/bootstrap.ps1 ./task_pwsh/bootstrap.ps1
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.11 && rm -rf /root/.cache
# Root inside the container only to use the mounted Docker socket, which is
# root-equivalent on the host anyway (threat-model §7.3).
CMD ["/srv/.venv/bin/python", "-m", "clw.runner"]
