# Task sandbox image (Task 14; SD-008; threat-model §7.1).
# Holds only the Python runtime, httpx, task_sdk/ and tasks/: no broker code,
# no profiles, no credentials. The final stage is copied onto scratch so the
# image carries no ENV of its own (the python base image sets PATH, LANG,
# GPG_KEY and PYTHON_*). Docker still adds PATH and HOSTNAME at run time; the
# runner adds exactly CLW_RUN_TOKEN and CLW_BROKER_URL.
FROM python:3.11-slim AS build
RUN pip install --no-cache-dir --no-compile "httpx==0.28.1" \
 && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin task \
 && rm -rf /root/.cache
COPY task_sdk/clw_task_sdk /app/clw_task_sdk
COPY tasks /app/tasks
RUN find /app -name "__pycache__" -prune -exec rm -rf {} + \
 && find /app/tasks -name "manifest.yaml" -delete

FROM scratch
COPY --from=build / /
WORKDIR /app
USER 10001:10001
