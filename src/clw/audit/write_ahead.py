"""Write-ahead protocol for one outbound attempt (SD-007, threat-model §5).

    intent committed  ->  send  ->  outcome committed  ->  data released

- If the intent cannot be recorded, send() is never called.
- If the outcome cannot be recorded, the data is discarded and
  AuditUnavailable is raised; the committed intent stays in the chain and
  the verifier lists it under intents_without_outcome.
- If send() fails, the failure is recorded as the outcome and re-raised;
  if that record cannot be written either, AuditUnavailable is raised.

The broker (Task 12) wires record_intent / record_outcome to AuditWriter
appends of GRAPH_REQUEST / GRAPH_RESPONSE events.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

from clw.audit.events import AuditUnavailable

T = TypeVar("T")


async def audited_attempt(
    *,
    record_intent: Callable[[], Awaitable[object]],
    send: Callable[[], Awaitable[T]],
    record_outcome: Callable[[T | None, BaseException | None], Awaitable[object]],
) -> T:
    try:
        await record_intent()
    except Exception as exc:
        raise AuditUnavailable("intent not recorded; request not sent") from exc

    try:
        result = await send()
    except Exception as send_error:
        try:
            await record_outcome(None, send_error)
        except Exception as audit_error:
            raise AuditUnavailable("request failed and its outcome could not be recorded") from audit_error
        raise

    try:
        await record_outcome(result, None)
    except Exception as exc:
        del result  # withhold: nothing derived from the response leaves this function
        raise AuditUnavailable("response not recorded; data withheld") from exc
    return result
