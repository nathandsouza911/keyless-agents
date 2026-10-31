"""Write-ahead protocol (SD-007): no request without a committed intent, no
data without a committed outcome. Fakes stand in for the writer and Graph."""

from __future__ import annotations

import pytest

from clw.audit.events import AuditUnavailable
from clw.audit.write_ahead import audited_attempt


class Recorder:
    def __init__(self, fail_intent=False, fail_outcome=False):
        self.fail_intent, self.fail_outcome = fail_intent, fail_outcome
        self.intents, self.outcomes = [], []

    async def intent(self):
        if self.fail_intent:
            raise ConnectionError("db down")
        self.intents.append(1)

    async def outcome(self, result, error):
        if self.fail_outcome:
            raise ConnectionError("db down")
        self.outcomes.append((result, error))


class Graph:
    def __init__(self, fail=False):
        self.calls, self.fail = 0, fail

    async def send(self):
        self.calls += 1
        if self.fail:
            raise TimeoutError("graph timeout")
        return {"value": ["secret-user-data"]}


async def test_success_records_intent_then_outcome_and_returns_data():
    rec, graph = Recorder(), Graph()
    result = await audited_attempt(record_intent=rec.intent, send=graph.send, record_outcome=rec.outcome)
    assert result == {"value": ["secret-user-data"]}
    assert rec.intents == [1] and rec.outcomes == [(result, None)] and graph.calls == 1


async def test_intent_failure_means_request_is_never_sent():
    rec, graph = Recorder(fail_intent=True), Graph()
    with pytest.raises(AuditUnavailable):
        await audited_attempt(record_intent=rec.intent, send=graph.send, record_outcome=rec.outcome)
    assert graph.calls == 0
    assert rec.outcomes == []


async def test_outcome_failure_withholds_data():
    rec, graph = Recorder(fail_outcome=True), Graph()
    with pytest.raises(AuditUnavailable) as info:
        await audited_attempt(record_intent=rec.intent, send=graph.send, record_outcome=rec.outcome)
    assert graph.calls == 1
    assert "secret-user-data" not in repr(info.value)
    assert "secret-user-data" not in repr(info.value.__cause__)


async def test_failed_request_is_recorded_then_reraised():
    rec, graph = Recorder(), Graph(fail=True)
    with pytest.raises(TimeoutError):
        await audited_attempt(record_intent=rec.intent, send=graph.send, record_outcome=rec.outcome)
    assert len(rec.outcomes) == 1
    result, error = rec.outcomes[0]
    assert result is None and isinstance(error, TimeoutError)


async def test_failed_request_with_unrecordable_outcome_is_audit_unavailable():
    rec, graph = Recorder(fail_outcome=True), Graph(fail=True)
    with pytest.raises(AuditUnavailable):
        await audited_attempt(record_intent=rec.intent, send=graph.send, record_outcome=rec.outcome)


async def test_audit_unavailable_from_intent_propagates_unwrapped_type():
    async def intent():
        raise AuditUnavailable("writer said no")

    graph = Graph()
    with pytest.raises(AuditUnavailable):
        await audited_attempt(record_intent=intent, send=graph.send, record_outcome=Recorder().outcome)
    assert graph.calls == 0


# ---------------------------------------------- cancellation (BaseException)

import asyncio


async def test_cancellation_while_recording_intent_never_sends():
    graph = Graph()

    async def intent():
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):  # propagates unwrapped, by design
        await audited_attempt(record_intent=intent, send=graph.send, record_outcome=Recorder().outcome)
    assert graph.calls == 0


async def test_cancellation_while_recording_outcome_releases_no_data():
    graph = Graph()

    async def outcome(result, error):
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError) as info:
        await audited_attempt(record_intent=Recorder().intent, send=graph.send, record_outcome=outcome)
    assert graph.calls == 1
    assert "secret-user-data" not in repr(info.value)
