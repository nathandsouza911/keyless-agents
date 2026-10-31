#!/usr/bin/env bash
# gVisor evaluation for script runs (Part B, M5; SD-044).
#
# Runs the Docker sandbox suites twice, under runc (the baseline) and under
# gVisor (runsc), and times container start-up, the analyser and a script
# run's PowerShell start-up under each. Writes everything to gvisor-eval/
# (git-ignored): results.md to send back, and the raw logs.
#
# It records the host it ran on: kernel (uname -r), OS, Docker and runsc
# versions. Results from one host are evidence of feasibility on that host,
# not of the pilot host, whose kernel, Docker and gVisor versions may differ
# and must be tested there.
#
# Needs: Docker with the runsc runtime registered, uv, and this repository.
# No tenant, no credentials, no network beyond pulling the base images.
#
# Installing gVisor (Debian/Kali; review before running, needs sudo):
#   curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
#   echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
#     https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
#   sudo apt-get update && sudo apt-get install -y runsc
#   sudo runsc install && sudo systemctl restart docker
#
# Usage: scripts/gvisor_eval.sh            (from the repository root)
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=gvisor-eval
mkdir -p "$OUT"
RESULTS="$OUT/results.md"

if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
    echo "runsc is not registered with Docker; see the install steps at the top of this script." >&2
    exit 2
fi
command -v uv >/dev/null || { echo "uv is required (https://docs.astral.sh/uv/)" >&2; exit 2; }

docker buildx version >/dev/null 2>&1 || {
    echo "docker buildx (BuildKit) is required: sudo apt-get install -y docker-buildx" >&2; exit 2; }

uv sync --python 3.11 --locked >/dev/null

# Builds show their progress: the PowerShell images download the Graph modules
# from the PowerShell Gallery (several hundred MB), which can take a while.
echo "== building images (1/3: escape probe)"
docker build --progress=plain -f docker/task-probe.Dockerfile -t clw-task-probe:test .
echo "== building images (2/3: script analyser)"
docker build --progress=plain -f docker/analyser.Dockerfile -t clw-analyser:test .
docker pull python:3.11-slim
docker network inspect clw_tasknet >/dev/null 2>&1 || docker network create --internal clw_tasknet >/dev/null
# The PowerShell image is built by its own tests with a throwaway CA; build one
# here too for the timings.
echo "== building images (3/3: PowerShell task image)"
EVAL_CA=$(mktemp -d)
uv run python -c "from clw.broker.facade.ca import create; import sys; create(sys.argv[1])" "$EVAL_CA"
docker build --progress=plain --build-context "facade_ca=$EVAL_CA/public" -f docker/task-pwsh.Dockerfile \
    -t clw-task-pwsh:gvisor-eval .
rm -rf "$EVAL_CA"

# The one sandbox test that also needs Postgres runs only if the compose
# database is up (it is about the runner's timeout, not the runtime).
PG_SELECT=(--deselect tests/db/test_sandbox_timeout.py)
if docker compose ps --status running postgres 2>/dev/null | grep -q postgres; then PG_SELECT=(); fi

suite() {  # $1 = runtime label, $2 = CLW_TASK_RUNTIME value
    local log="$OUT/sandbox-$1.log" start end
    start=$(date +%s)
    if CLW_TASK_RUNTIME="$2" uv run pytest -m sandbox -p no:cacheprovider -q -rfE "${PG_SELECT[@]}" >"$log" 2>&1; then
        :
    fi
    end=$(date +%s)
    echo "| $1 | $(tail -n 1 "$log") | $((end - start)) s |"
}

median_ms() {  # runs "$@" five times; the median wall time, or "failed" (a failed run is never timed)
    local times=() t0 t1
    for _ in 1 2 3 4 5; do
        t0=$(date +%s%N)
        if ! "$@" >>"$OUT/timings.log" 2>&1; then echo "failed (see $OUT/timings.log)"; return; fi
        t1=$(date +%s%N)
        times+=($(( (t1 - t0) / 1000000 )))
    done
    echo "$(printf '%s\n' "${times[@]}" | sort -n | sed -n 3p) ms"
}

timings() {  # $1 = runtime
    local rt=(--runtime "$1")
    local hello pwsh analyse
    hello=$(median_ms docker run --rm "${rt[@]}" --network none python:3.11-slim true)
    pwsh=$(median_ms docker run --rm "${rt[@]}" --network none --read-only --tmpfs /tmp --entrypoint pwsh \
        clw-task-pwsh:gvisor-eval -NoProfile -Command 'Import-Module Microsoft.Graph.Users')
    analyse=$(median_ms sh -c "docker run --rm -i ${rt[*]} --network none --read-only --tmpfs /tmp --memory 1g \
        clw-analyser:test < tests/fixtures/scripts/inactive_users_demo.ps1")
    echo "| $1 | ${hello} | ${pwsh} | ${analyse} |"
}

echo "== sandbox suites (this takes a few minutes)"
{
    echo "# gVisor evaluation: $(date -u +%Y-%m-%dT%H:%MZ)"
    echo
    echo "Evidence of feasibility on this host only, not of the pilot host (SD-044)."
    echo
    echo "## Host"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Kernel (uname -r) | $(uname -r) |"
    echo "| OS | $(. /etc/os-release && echo "$PRETTY_NAME") |"
    echo "| Docker (server) | $(docker version --format '{{.Server.Version}}') |"
    echo "| runsc | $(runsc --version 2>/dev/null | head -n 1) |"
    echo "| cgroup | $(docker info --format '{{.CgroupVersion}}') (driver $(docker info --format '{{.CgroupDriver}}')) |"
    echo "| CPU | $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) cores) |"
    echo "| Repository commit | $(git rev-parse --short HEAD) |"
    echo
    echo "## Sandbox suites"
    echo
    echo "| Runtime | Result | Time |"
    echo "|---|---|---|"
    suite runc ""
    suite runsc runsc
    echo
    echo "## Timings (median of 5)"
    echo
    echo "| Runtime | Container start | PowerShell + Microsoft.Graph.Users import | Analyser on the fixture script |"
    echo "|---|---|---|---|"
    timings runc
    timings runsc
    echo
    echo "Failures under runsc (if any) are in $OUT/sandbox-runsc.log."
} | tee "$RESULTS"

echo
echo "Done: send $RESULTS (and $OUT/sandbox-runsc.log if anything failed)."
