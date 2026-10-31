# E2E-only layer over the real runner image (Task 17A). Adds the test-only
# demo task (manifest + task.py) so the runner's catalog binds it and can
# build its command. The production runner image is unchanged.
FROM clw-runner-base:latest
COPY tests/e2e/demo_task /srv/tasks/dormant_probe_demo
