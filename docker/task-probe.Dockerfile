# Escape-probe image (Task 15; test-only, never shipped).
# Mirrors docker/task.Dockerfile (scratch final stage, so the image carries no
# ENV of its own and the env test sees only what the runner injects) but adds
# curl ON PURPOSE, so the subprocess test proves that even a task with a real
# HTTP client and a shell has no route off tasknet. It carries the escape probe
# instead of the shipped tasks. Built as clw-task-probe:test.
# /probe-owned is owned by the task user, so a write there can fail only
# because the root filesystem is read-only (EROFS), under runc and gVisor alike.
FROM python:3.11-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && pip install --no-cache-dir --no-compile "httpx==0.28.1" \
 && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin task \
 && mkdir /probe-owned && chown 10001:10001 /probe-owned \
 && rm -rf /var/lib/apt/lists/* /root/.cache
COPY task_sdk/clw_task_sdk /app/clw_task_sdk
COPY tests/fixtures/tasks/escape_probe /app/tasks/escape_probe
RUN : > /app/tasks/__init__.py \
 && find /app -name "__pycache__" -prune -exec rm -rf {} +

FROM scratch
COPY --from=build / /
WORKDIR /app
USER 10001:10001
