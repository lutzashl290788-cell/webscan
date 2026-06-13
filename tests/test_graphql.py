"""Tests for the GraphQL introspection plugin."""
from __future__ import annotations

import json

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.graphql import GraphqlPlugin, _introspection_enabled
from webscan.retry import RetryConfig

_NO_RETRY = RetryConfig(retries=0, base_delay=0.0)


def test_introspection_enabled_detects_schema() -> None:
    body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
    assert _introspection_enabled(body) is True


def test_introspection_enabled_rejects_plain_json() -> None:
    assert _introspection_enabled(json.dumps({"data": {"foo": 1}})) is False
    assert _introspection_enabled("not json") is False
    assert _introspection_enabled(json.dumps({"errors": ["x"]})) is False


async def test_flags_endpoint_with_introspection() -> None:
    body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
    session = FakeSession(FakeResponse(status=200, body=body))

    findings = await GraphqlPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )

    assert findings, "expected at least one introspection finding"
    assert all(f.severity is Severity.MEDIUM for f in findings)
    assert all(f.evidence["introspection"] is True for f in findings)
    # All probes were POSTed.
    assert all(verb == "POST" for verb, _url, _kw in session.requests)


async def test_no_findings_when_endpoint_absent() -> None:
    session = FakeSession(FakeResponse(status=404, body=""))
    findings = await GraphqlPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )
    assert findings == []


async def test_no_findings_for_non_graphql_200() -> None:
    session = FakeSession(FakeResponse(status=200, body='{"data":{"foo":1}}'))
    findings = await GraphqlPlugin(retry=_NO_RETRY).run(
        "https://example.com", session,  # type: ignore[arg-type]
    )
    assert findings == []
