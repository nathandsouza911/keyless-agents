"""Task SDK client and result line (Task 13; architecture.md §3; SD-002, SD-008).

The broker is mocked with respx. What the broker does with a request is
tested in tests/db/test_broker_ops.py and, with this client,
tests/db/test_task_sdk_broker.py.
"""

from __future__ import annotations

import io
import json
import logging
import math
import ssl
import traceback

import httpx
import pytest
import respx

from clw_task_sdk import client as client_module
from clw_task_sdk.client import (
    LIST_USERS, USER_FIELDS, BrokerError, GraphSecurityClient, OperationDenied,
)
from clw_task_sdk.result import RESULT_PREFIX, emit_result

BROKER = "http://broker:8080"
OPS = BROKER + "/v1/ops"
TOKEN = "T" * 21 + "_-" + "k" * 20  # 43 URL-safe characters, generated shape only
USERS = [{"id": "u-1", "signInActivity": None}]


@pytest.fixture
def broker():
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as mock:
        yield mock.post(OPS)


def ok(data=USERS) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok", "data": data})


def sdk(**kwargs) -> GraphSecurityClient:
    return GraphSecurityClient(BROKER, TOKEN, **kwargs)


def sent(route) -> list[dict]:
    return [json.loads(call.request.content) for call in route.calls]


# ------------------------------------------------------------ what is sent


def test_sdk_sends_only_op_and_params(broker):
    broker.mock(return_value=ok())
    sdk().call(LIST_USERS, {"select": ["id"]})
    (call,) = broker.calls
    assert json.loads(call.request.content) == {"op": LIST_USERS, "params": {"select": ["id"]}}
    assert (call.request.method, str(call.request.url)) == ("POST", OPS)
    assert call.request.headers["authorization"] == f"RunToken {TOKEN}"
    assert call.request.headers["content-type"] == "application/json"


def test_list_users_names_the_operation_not_a_path(broker):
    broker.mock(return_value=ok())
    assert sdk().list_users_with_sign_in_activity() == USERS
    (payload,) = sent(broker)
    assert payload == {"op": "users.list_with_sign_in_activity", "params": {"select": list(USER_FIELDS)}}
    text = json.dumps(payload)
    for forbidden in ("/users", "graph.microsoft.com", "v1.0", "path", "url", "method", "$top", "top"):
        assert forbidden not in text


def test_user_fields_are_what_classification_and_the_result_need():
    assert set(USER_FIELDS) == {"id", "displayName", "userPrincipalName", "accountEnabled", "createdDateTime",
                                "signInActivity"}


def test_params_are_sent_unchanged_without_a_path(broker):
    # The SDK adds nothing; whatever the task passes is judged by the broker.
    broker.mock(return_value=ok())
    sdk().call("users.update", {"user_id": "00000000-0000-0000-0000-000000000001"})
    assert sent(broker) == [{"op": "users.update", "params": {"user_id": "00000000-0000-0000-0000-000000000001"}}]


@pytest.mark.parametrize("op, params, error", [
    (None, {}, TypeError), (1, {}, TypeError), (LIST_USERS, None, TypeError), (LIST_USERS, [], TypeError),
    (LIST_USERS, {"top": math.nan}, ValueError), (LIST_USERS, {"top": math.inf}, ValueError),
    (LIST_USERS, {"x": object()}, TypeError),
])
def test_unsendable_calls_send_nothing(broker, op, params, error):
    with pytest.raises(error):
        sdk().call(op, params)
    assert broker.calls.call_count == 0


# ------------------------------------------------------------ the environment


class RecordingEnviron(dict):
    def __init__(self, values):
        super().__init__(values)
        self.read: list[str] = []

    def get(self, key, default=None):
        self.read.append(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self.read.append(key)
        return super().__getitem__(key)


def test_from_env_reads_only_the_two_keys(monkeypatch):
    environ = RecordingEnviron({"CLW_RUN_TOKEN": TOKEN, "CLW_BROKER_URL": BROKER, "HTTP_PROXY": "http://evil",
                                "AZURE_CLIENT_SECRET": "x"})
    monkeypatch.setattr(client_module.os, "environ", environ)
    client = GraphSecurityClient.from_env()
    assert set(environ.read) == {"CLW_RUN_TOKEN", "CLW_BROKER_URL"}
    assert client.broker_url == OPS


def test_http_client_ignores_proxy_and_netrc_settings():
    http = sdk()._http
    assert http.trust_env is False and http.follow_redirects is False


def test_tls_key_log_variable_is_ignored(monkeypatch, tmp_path):
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    GraphSecurityClient("https://broker", TOKEN).close()
    assert not keylog.exists()


def test_tls_context_verifies_the_broker():
    context = client_module._tls_context()
    assert context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2 and context.keylog_filename is None


def test_proxy_variables_do_not_reroute(monkeypatch, broker):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    broker.mock(return_value=ok())
    sdk().call(LIST_USERS, {})
    assert str(broker.calls.last.request.url) == OPS


@pytest.mark.parametrize("missing", ["CLW_RUN_TOKEN", "CLW_BROKER_URL"])
@pytest.mark.parametrize("value", [None, ""])
def test_from_env_requires_both(monkeypatch, missing, value):
    monkeypatch.setenv("CLW_RUN_TOKEN", TOKEN)
    monkeypatch.setenv("CLW_BROKER_URL", BROKER)
    if value is None:
        monkeypatch.delenv(missing)
    else:
        monkeypatch.setenv(missing, value)
    with pytest.raises(ValueError, match=missing):
        GraphSecurityClient.from_env()


@pytest.mark.parametrize("url", [
    "broker:8080", "ftp://broker", "file:///etc/passwd", "http://", "http://user:pw@broker:8080",
    "http://broker:8080/v1", "http://broker:8080/?x=1", "http://broker:8080/#f", "http://broker:8080\n",
    "http://bro ker", " http://broker", "http://broker:99999", "http://broker:0", "http://-broker",
    "http://broker:8080:1", "HTTP://broker",
])
def test_broker_url_must_be_a_bare_http_origin(url):
    with pytest.raises(ValueError):
        GraphSecurityClient(url, TOKEN)


@pytest.mark.parametrize("url, expected", [
    ("http://broker:8080", OPS), ("http://broker:8080/", OPS), ("https://broker", "https://broker/v1/ops"),
])
def test_broker_url_forms(url, expected):
    assert GraphSecurityClient(url, TOKEN).broker_url == expected


@pytest.mark.parametrize("token", ["", "a b", "tok\r\nX-Evil: 1", "té", "a" * 42, "a" * 44, "a/b" + "c" * 40,
                                   None, 123])
def test_run_token_must_have_the_issued_shape(token):
    with pytest.raises(ValueError) as caught:
        GraphSecurityClient(BROKER, token)
    if isinstance(token, str) and token:
        assert token not in str(caught.value)


# ------------------------------------------------------------ what comes back


@pytest.mark.parametrize("status", [401, 403])
def test_denial_raises_operation_denied_with_reason(broker, status):
    broker.mock(return_value=httpx.Response(status, json={"status": "denied", "reason": "not_in_manifest"}))
    with pytest.raises(OperationDenied) as caught:
        sdk().call("users.update", {})
    assert caught.value.reason == "not_in_manifest" and str(caught.value) == "not_in_manifest"


@pytest.mark.parametrize("status, body, reason", [
    (502, {"status": "failed", "reason": "licence_required"}, "licence_required"),
    (503, {"status": "error", "reason": "audit_unavailable"}, "audit_unavailable"),
])
def test_run_failures_raise_broker_error(broker, status, body, reason):
    broker.mock(return_value=httpx.Response(status, json=body))
    with pytest.raises(BrokerError) as caught:
        sdk().list_users_with_sign_in_activity()
    assert (caught.value.reason, caught.value.status_code) == (reason, status)
    assert not isinstance(caught.value, OperationDenied)


@pytest.mark.parametrize("response", [
    httpx.Response(200, json={"status": "ok"}),
    httpx.Response(200, json={"status": "ok", "data": {"value": []}}),
    httpx.Response(200, json={"status": "denied", "reason": "x", "data": []}),
    httpx.Response(200, json=["status", "ok"]),
    httpx.Response(200, text="<html>ok</html>"),
    httpx.Response(200, content=b"\xff\xfe"),
    httpx.Response(403, json={"status": "ok", "data": []}),
    httpx.Response(403, text="Forbidden"),
    httpx.Response(500, json={"status": "error", "reason": "x"}),
    httpx.Response(502, json={"status": "denied", "reason": "x"}),
    httpx.Response(204),
    httpx.Response(302, headers={"location": "https://graph.microsoft.com/v1.0/users"}),
], ids=lambda r: str(r.status_code))
def test_unexpected_replies_are_errors_never_data(broker, response):
    broker.mock(return_value=response)
    with pytest.raises(BrokerError) as caught:
        sdk().call(LIST_USERS, {})
    assert caught.value.reason == "invalid_broker_response"
    assert broker.calls.call_count == 1  # no redirect followed, nothing retried


@pytest.mark.parametrize("data", [[1], ["u"], [None], [{"id": "u"}, []]])
def test_list_users_requires_objects(broker, data):
    broker.mock(return_value=ok(data))
    with pytest.raises(BrokerError, match="invalid_broker_response"):
        sdk().list_users_with_sign_in_activity()


@pytest.mark.parametrize("reason", ["x\nCLW_RESULT {}", "", "A" * 65, 7, None, "Not-Snake", "a b"])
def test_reasons_from_the_broker_are_sanitized(broker, reason):
    broker.mock(return_value=httpx.Response(403, json={"status": "denied", "reason": reason}))
    with pytest.raises(OperationDenied) as caught:
        sdk().call(LIST_USERS, {})
    assert caught.value.reason == "unknown"


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"),
                                   httpx.RemoteProtocolError("cut")])
def test_transport_failure_is_one_attempt_and_an_error(broker, error):
    broker.mock(side_effect=error)
    with pytest.raises(BrokerError) as caught:
        sdk().call(LIST_USERS, {})
    assert (caught.value.reason, caught.value.status_code) == ("broker_unreachable", None)
    assert broker.calls.call_count == 1


@pytest.mark.parametrize("status", [429, 502, 503])
def test_nothing_is_retried(broker, status):
    # The broker owns retries; a client retry would execute the operation again.
    broker.mock(return_value=httpx.Response(status, json={"status": "error", "reason": "busy"}))
    with pytest.raises(BrokerError):
        sdk().call(LIST_USERS, {})
    assert broker.calls.call_count == 1


# ------------------------------------------------------------ the token stays out of text


def test_token_not_in_repr_errors_tracebacks_or_logs(broker, caplog):
    caplog.set_level(logging.DEBUG)
    client = sdk()
    assert TOKEN not in repr(client) and TOKEN not in str(client)
    texts = []
    for response in (httpx.Response(403, json={"status": "denied", "reason": "x"}), httpx.Response(500),
                     httpx.ConnectError("refused")):
        broker.mock(**({"side_effect": response} if isinstance(response, Exception) else {"return_value": response}))
        with pytest.raises(BrokerError) as caught:
            client.call(LIST_USERS, {})
        texts += [str(caught.value), repr(caught.value),
                  "".join(traceback.format_exception(caught.value))]
    texts.append(caplog.text)
    assert not [t for t in texts if TOKEN in t]


def test_operation_denied_is_a_broker_error():
    # A task catching BrokerError cannot miss a denial.
    assert issubclass(OperationDenied, BrokerError)


def test_client_closes(broker):
    with sdk() as client:
        pass
    assert client._http.is_closed


# ------------------------------------------------------------ the result line


def test_emit_result_writes_one_prefixed_json_line():
    out = io.StringIO()
    emit_result({"b": 1, "a": "x\ny", "u": "café    "}, stream=out)
    text = out.getvalue()
    assert text.endswith("\n") and text.count("\n") == 1 and text.startswith(RESULT_PREFIX)
    assert text.isascii()  # U+2028/2029 escaped: no other line breaks for a line splitter to find
    assert len(text.splitlines()) == 1
    assert json.loads(text[len(RESULT_PREFIX):]) == {"a": "x\ny", "b": 1, "u": "café    "}


def test_emit_result_defaults_to_stdout(capsys):
    emit_result({"ok": True})
    assert capsys.readouterr().out == 'CLW_RESULT {"ok":true}\n'  # the plan's literal line (the runner parses it)


def test_emit_result_flushes():
    # A task that exits (or is killed) right after emitting must not lose the line in a buffer.
    class Recorder(io.StringIO):
        flushed_with = None

        def flush(self):
            self.flushed_with = self.getvalue()
            super().flush()

    out = Recorder()
    emit_result({"ok": True}, stream=out)
    assert out.flushed_with == 'CLW_RESULT {"ok":true}\n'


@pytest.mark.parametrize("payload, error", [
    ([], TypeError), ("x", TypeError), (None, TypeError), ({"x": math.nan}, ValueError),
    ({"x": object()}, TypeError), ({1: "x"}, TypeError), ({"x": {2: "y"}}, TypeError),
])
def test_emit_result_rejects_and_writes_nothing(payload, error):
    out = io.StringIO()
    with pytest.raises(error):
        emit_result(payload, stream=out)
    assert out.getvalue() == ""
