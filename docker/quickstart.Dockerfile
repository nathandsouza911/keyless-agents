# Quick start image (SD-051): the setup, the fake Graph, the demo broker and the api, from one build so the
# quick start installs dependencies once. Demo mode only: clw.demo refuses production and real credentials.
FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.23 /uv /usr/local/bin/uv
RUN useradd --uid 10010 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin quickstart
WORKDIR /srv
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY task_sdk ./task_sdk
COPY profiles ./profiles
COPY tasks ./tasks
COPY agent_profiles ./agent_profiles
COPY alembic.ini ./
COPY migrations ./migrations
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.11 && rm -rf /root/.cache
USER 10010:10010
