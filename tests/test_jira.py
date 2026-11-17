"""Jira Cloud tracker against a mocked HTTP transport (FR-DS-01, FR-DS-04)."""

from __future__ import annotations

import json
from datetime import date

import httpx
import pytest

from kavlotryx.dispatch.base import TrackerError
from kavlotryx.dispatch.jira import JiraCloudTracker, adf


def make(handler, sleeps=None):
    return JiraCloudTracker("https://acme.atlassian.net", "bot@example.com", "tok",
                            transport=httpx.MockTransport(handler),
                            sleep=(sleeps.append if sleeps is not None else lambda _: None))


def test_create_sends_labels_adf_and_due_date():
    seen = {}

    def h(req: httpx.Request):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(201, json={"key": "PAY-1"})

    t = make(h).create("PAY", "Upgrade openssl", "line one\n\n<script>x</script>", "High",
                       ["kavlotryx", "kavlo-abc"], date(2026, 12, 17))
    f = seen["body"]["fields"]
    assert t.key == "PAY-1" and t.url == "https://acme.atlassian.net/browse/PAY-1"
    assert f["labels"] == ["kavlotryx", "kavlo-abc"]
    assert f["duedate"] == "2026-12-17"
    assert f["description"]["content"][2]["content"][0] == {"type": "text", "text": "<script>x</script>"}
    assert seen["auth"].startswith("Basic ")


def test_priority_fallback_on_400():
    calls = []

    def h(req):
        body = json.loads(req.content)
        calls.append("priority" in body["fields"])
        if "priority" in body["fields"]:
            return httpx.Response(400, json={"errors": {"priority": "not valid"}})
        return httpx.Response(201, json={"key": "PAY-2"})

    assert make(h).create("PAY", "s", "d", "Highest", ["kavlo-x"], None).key == "PAY-2"
    assert calls == [True, False]


def test_retry_after_on_429():
    sleeps, n = [], {"i": 0}

    def h(req):
        n["i"] += 1
        if n["i"] < 3:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"issues": []})

    assert make(h, sleeps).find_by_label("kavlo-abc") is None
    assert sleeps == [7.0, 7.0]


def test_search_uses_label_jql():
    def h(req):
        body = json.loads(req.content)
        assert req.url.path == "/rest/api/3/search/jql"
        assert body["jql"].startswith('labels = "kavlo-abc"')
        return httpx.Response(200, json={"issues": [
            {"key": "PAY-9", "fields": {"status": {"statusCategory": {"key": "indeterminate"}}}}]})

    t = make(h).find_by_label("kavlo-abc")
    assert (t.key, t.status) == ("PAY-9", "indeterminate")


def test_label_injection_rejected():
    with pytest.raises(TrackerError):
        make(lambda r: httpx.Response(200)).find_by_label('x" OR project = SECRET')


def test_transition_picks_done_category():
    posted = {}

    def h(req):
        if req.method == "GET":
            return httpx.Response(200, json={"transitions": [
                {"id": "11", "to": {"statusCategory": {"key": "indeterminate"}}},
                {"id": "31", "to": {"statusCategory": {"key": "done"}}}]})
        posted["body"] = json.loads(req.content)
        return httpx.Response(204)

    make(h).transition("PAY-1", "done")
    assert posted["body"] == {"transition": {"id": "31"}}


def test_status_missing_and_errors():
    assert make(lambda r: httpx.Response(404)).status("PAY-404") == "missing"
    with pytest.raises(TrackerError, match="HTTP 403"):
        make(lambda r: httpx.Response(403, text="no")).status("PAY-1")


def test_https_required():
    with pytest.raises(TrackerError):
        JiraCloudTracker("http://jira.local", "a", "b")


def test_adf_blank_lines():
    doc = adf("a\n\nb")
    assert [len(p["content"]) for p in doc["content"]] == [1, 0, 1]
