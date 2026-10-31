"""`python -m clw.runner`: the runner process (Task 14).

Configuration comes from the runner's own environment, never from a run:
DATABASE_URL (via clw.common.config), CLW_TASK_IMAGE and CLW_TASK_BROKER_URL
(the URL tasks use to reach the broker on tasknet), CLW_ANALYSER_IMAGE
(the offline script analyser, SD-043; without it scripts stay unanalysed),
CLW_SCRIPT_IMAGE with CLW_SCRIPT_BROKER_URL (the PowerShell task image and
the Graph host's URL as scripts see it, SD-044; without the image script runs
stay queued) and CLW_TASK_RUNTIME (the container runtime for every task,
script and analysis container, for example runsc for gVisor; without it
Docker's default).
The reconciler sweeps at start-up and every minute; the launcher starts
queued runs one at a time, and the analyser analyses queued scripts.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

from clw.runner.sandbox_spec import SandboxConfig, ScriptSandboxConfig, bootstrap_sha256

POLL_SECONDS = 2.0
SWEEP_SECONDS = 60.0


async def _serve() -> None:  # pragma: no cover - wiring only; needs the deployment
    from clw.audit.writer import AuditWriter
    from clw.db.session import get_sessionmaker
    from clw.runner.backend import DockerBackend
    from clw.runner.catalog import load_task_catalog
    from clw.runner.launcher import Launcher
    from clw.runner.analyser import Analyser
    from clw.runner.reconciler import Reconciler

    runtime = os.environ.get("CLW_TASK_RUNTIME") or None
    config = SandboxConfig(image=os.environ["CLW_TASK_IMAGE"], broker_url=os.environ["CLW_TASK_BROKER_URL"],
                           runtime=runtime)
    script_image = os.environ.get("CLW_SCRIPT_IMAGE")
    script_config = ScriptSandboxConfig(image=script_image, broker_url=os.environ["CLW_SCRIPT_BROKER_URL"],
                                         runtime=runtime) if script_image else None
    sessionmaker = get_sessionmaker()
    writer = AuditWriter(sessionmaker)
    backend = DockerBackend()
    launcher = Launcher(sessionmaker=sessionmaker, writer=writer, backend=backend, catalog=load_task_catalog(),
                        config=config, script_config=script_config,
                        bootstrap_sha256=bootstrap_sha256() if script_config else None)
    reconciler = Reconciler(sessionmaker=sessionmaker, writer=writer, backend=backend)
    image = os.environ.get("CLW_ANALYSER_IMAGE")
    analyser = (Analyser(sessionmaker=sessionmaker, writer=writer, backend=backend, image=image, runtime=runtime)
                if image else None)
    last_sweep = float("-inf")
    while True:
        if time.monotonic() - last_sweep >= SWEEP_SECONDS:
            await reconciler.sweep()
            last_sweep = time.monotonic()
        launched = await launcher.run_once()
        analysed = await analyser.run_once() if analyser is not None else None
        if launched is None and analysed is None:
            await asyncio.sleep(POLL_SECONDS)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_serve())
