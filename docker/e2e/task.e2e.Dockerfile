# E2E-only layer over the real task sandbox image (Task 17A). Adds the
# test-only demo task module so the sandbox can run it. The module imports the
# shipped classifier and the task SDK, both already in the image. The
# production task image (docker/task.Dockerfile) is unchanged.
FROM clw-task-base:latest
COPY tests/e2e/demo_task /app/tasks/dormant_probe_demo
