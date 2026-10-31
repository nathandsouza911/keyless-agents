"""Tenant-scoped audit verification (Task 16).

    GET /audit/verify   verify the caller's whole tenant audit chain

The chain verified is the caller's own tenant chain (`principal.tid`), never
a tenant named in the request. The result reports whether the chain is valid,
how long it is, its head sequence, any integrity errors (as `seq` + `issue`,
no record contents), and the sequence numbers of Graph intents that have no
recorded outcome. It exposes no other tenant's data and no credential or
token (the audit records hold none by design).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from clw.api.deps import Principal, current_principal
from clw.api.runtime import get_sessionmaker
from clw.audit.verifier import verify_chain

router = APIRouter(prefix="/audit")


@router.get("/verify", name="audit_verify")
async def verify(
    principal: Principal = Depends(current_principal),
    sessionmaker=Depends(get_sessionmaker),
) -> dict:
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=principal.tid)
    return {
        "valid": report.valid,
        "total": report.total,
        "head_seq": report.head_seq,
        "errors": [{"seq": e.seq, "issue": e.issue} for e in report.errors],
        "intents_without_outcome": list(report.intents_without_outcome),
    }
