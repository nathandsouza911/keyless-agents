#!/bin/sh
# Loop the pg test suite on Linux under parallel load, to tell an environmental flake from a real one.
#
#   scripts/pg_stress.sh [copies] [rounds]      (defaults: 4 copies, 3 rounds each)
#
# Each copy runs in its own Linux container (python:3.11-slim) against its own Postgres 15
# container on a private Docker network, so copies share CPU, memory and the Docker daemon
# but never a database or a role. Results: .pg-stress/copy-<n>-round-<r>.log and a summary.
set -eu
COPIES="${1:-4}"
ROUNDS="${2:-3}"
NET="clw-pg-stress"
OUT=".pg-stress"
# Git Bash on Windows: hand Docker a Windows path and stop MSYS rewriting /src-style arguments.
REPO="$(pwd -W 2>/dev/null || pwd)"
export MSYS_NO_PATHCONV=1
mkdir -p "$OUT"
docker network create "$NET" >/dev/null 2>&1 || true

cleanup() {
  for n in $(seq 1 "$COPIES"); do docker rm -f "clw-stress-pg-$n" "clw-stress-run-$n" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for n in $(seq 1 "$COPIES"); do
  docker run -d --name "clw-stress-pg-$n" --network "$NET" -e POSTGRES_USER=clw \
    -e POSTGRES_PASSWORD=stress-only -e POSTGRES_DB=clw postgres:15 >/dev/null
done
for n in $(seq 1 "$COPIES"); do
  until docker exec "clw-stress-pg-$n" pg_isready -U clw -d clw >/dev/null 2>&1; do sleep 1; done
done

for n in $(seq 1 "$COPIES"); do
  docker run -d --name "clw-stress-run-$n" --network "$NET" -v "$REPO:/src:ro" \
    -e TEST_PG_ADMIN_DSN="postgresql://clw:stress-only@clw-stress-pg-$n:5432/clw" \
    -e ROUNDS="$ROUNDS" -e COPY="$n" python:3.11-slim sh -c '
      set -u
      pip install -q uv >/dev/null 2>&1
      mkdir -p /work && cd /src && tar --exclude=./.venv --exclude=./.git --exclude=./.pg-stress -cf - . | tar -xf - -C /work
      cd /work && uv sync -q --python 3.11 --locked >/dev/null 2>&1
      for r in $(seq 1 "$ROUNDS"); do
        uv run pytest -m pg -q -p no:cacheprovider > "/tmp/round-$r.log" 2>&1
        echo "copy $COPY round $r exit $?"; tail -1 "/tmp/round-$r.log"
        cat "/tmp/round-$r.log" > /dev/stderr
      done' >/dev/null
done

status=0
for n in $(seq 1 "$COPIES"); do
  docker wait "clw-stress-run-$n" >/dev/null
  docker logs "clw-stress-run-$n" > "$OUT/copy-$n.summary" 2> "$OUT/copy-$n.log"
  cat "$OUT/copy-$n.summary"
  grep -q "exit [^0]" "$OUT/copy-$n.summary" && status=1
done
exit $status
