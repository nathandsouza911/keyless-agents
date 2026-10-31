# E2E-only layer over the real broker image (Task 17A). Adds the test-only
# demo task's manifest so the broker's and API's catalogs can bind a run of it.
# The production broker image (docker/broker.Dockerfile) is unchanged.
FROM clw-broker-base:latest
COPY tests/e2e/demo_task /srv/tasks/dormant_probe_demo
