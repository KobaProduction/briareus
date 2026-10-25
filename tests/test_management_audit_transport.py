from __future__ import annotations

import json
import unittest
from email.message import Message
from unittest.mock import Mock

from common.account_contracts import InvocationEvent
from common.http_transport import HttpTransportError, HttpTransportResponse, PooledHttpTransport
from common.management_client import ManagementClient


class _Response:
    status = 204
    will_close = False
    headers = Message()

    def read(self) -> bytes:
        return b""


class _Connection:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.closed = False
        self.requests = 0

    def request(self, *_args: object, **_kwargs: object) -> None:
        self.requests += 1
        if self.fail:
            raise BrokenPipeError(32, "closed keepalive")

    def getresponse(self) -> _Response:
        return _Response()

    def close(self) -> None:
        self.closed = True


class AuditTransportTests(unittest.TestCase):
    def test_audit_uses_new_connection_without_reusing_idle_pool(self) -> None:
        opened: list[_Connection] = []

        def factory() -> _Connection:
            connection = _Connection()
            opened.append(connection)
            return connection

        pool = PooledHttpTransport(factory, max_connections=2)
        pool.request("GET", "/health")
        self.assertEqual(pool.connection_count, 1)
        pool.request(
            "POST", "/internal/events/batch", body=b"{}",
            reconnect_retries=0, fresh_connection=True,
        )
        pool.request(
            "POST", "/internal/events/batch", body=b"{}",
            reconnect_retries=0, fresh_connection=True,
        )
        self.assertEqual(len(opened), 3)
        self.assertEqual(opened[0].requests, 1)
        self.assertFalse(opened[0].closed)
        self.assertTrue(opened[1].closed)
        self.assertTrue(opened[2].closed)
        self.assertEqual(pool.connection_count, 1)

    def test_failed_audit_is_never_replayed_automatically(self) -> None:
        opened: list[_Connection] = []

        def factory() -> _Connection:
            connection = _Connection(fail=True)
            opened.append(connection)
            return connection

        pool = PooledHttpTransport(factory, max_connections=2)
        with self.assertRaises(HttpTransportError):
            pool.request(
                "POST", "/internal/events/batch", body=b"{}",
                reconnect_retries=0, fresh_connection=True,
            )
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0].requests, 1)
        self.assertTrue(opened[0].closed)
        self.assertEqual(pool.connection_count, 0)

    def test_management_audit_chooses_fresh_nonretryable_transport(self) -> None:
        client = ManagementClient.__new__(ManagementClient)
        client._base_path = ""
        client.service_token = "dummy"
        client._transport = Mock()
        client._transport.request.return_value = HttpTransportResponse(
            status=204, headers={}, body=b"", will_close=False
        )
        client.record_invocations(
            [InvocationEvent(module="web", tool="browser_status", status="success", duration_ms=1)]
        )
        _, kwargs = client._transport.request.call_args
        self.assertEqual(kwargs["reconnect_retries"], 0)
        self.assertTrue(kwargs["fresh_connection"])
        self.assertEqual(json.loads(kwargs["body"])["events"][0]["tool"], "browser_status")


if __name__ == "__main__":
    unittest.main()
