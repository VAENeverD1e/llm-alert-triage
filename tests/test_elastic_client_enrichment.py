"""
Unit tests for ElasticClient's enrichment queries. These monkeypatch
requests.post so they run without a live Elasticsearch cluster, while
still exercising the real query-building and error-handling logic that
will run against the actual 192.168.75.11 lab cluster.
"""
import requests

from integrations.elastic_client import ElasticClient


class _FakeResponse:
    def __init__(self, hits, status=200):
        self._hits = hits
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"status {self.status_code}")

    def json(self):
        return {"hits": {"hits": self._hits}}


def test_get_process_creation_context_uses_entity_id_when_available(monkeypatch):
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["url"] = url
        captured["query"] = json
        hit = {"_source": {"process": {"parent": {"name": "cmd.exe", "pid": 111}}}}
        return _FakeResponse([hit])

    monkeypatch.setattr(requests, "post", fake_post)

    client = ElasticClient(host="http://es.lab:9200", api_key="k")
    result = client.get_process_creation_context(entity_id="guid-123")

    assert result == {"name": "cmd.exe", "executable": None, "command_line": None, "pid": 111}
    must_clauses = captured["query"]["query"]["bool"]["must"]
    assert {"term": {"event.code": "1"}} in must_clauses
    assert {"term": {"process.entity_id": "guid-123"}} in must_clauses


def test_get_process_creation_context_falls_back_to_pid_host_time(monkeypatch):
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["query"] = json
        return _FakeResponse([])

    monkeypatch.setattr(requests, "post", fake_post)
    client = ElasticClient()
    result = client.get_process_creation_context(
        pid=4548, host_name="desktop-thonlnr", timestamp="2026-04-21T08:54:08.208Z"
    )

    assert result is None
    must_clauses = captured["query"]["query"]["bool"]["must"]
    assert {"term": {"process.pid": 4548}} in must_clauses
    assert {"term": {"host.name": "desktop-thonlnr"}} in must_clauses
    assert any("range" in c for c in must_clauses)


def test_get_process_creation_context_refuses_unscoped_query():
    """No entity_id, pid, or host_name at all -- must not fire a query
    that would match arbitrary Event ID 1 records across the cluster."""
    client = ElasticClient()
    result = client.get_process_creation_context()
    assert result is None


def test_get_process_creation_context_returns_none_when_match_has_no_parent(monkeypatch):
    def fake_post(url, headers, json, timeout):
        hit = {"_source": {"process": {}}}  # matched, but no parent recorded
        return _FakeResponse([hit])

    monkeypatch.setattr(requests, "post", fake_post)
    client = ElasticClient()
    assert client.get_process_creation_context(entity_id="guid-x") is None


def test_resolve_host_from_ip_returns_name_on_match(monkeypatch):
    def fake_post(url, headers, json, timeout):
        hit = {"_source": {"host": {"name": "elk-siem"}}}
        return _FakeResponse([hit])

    monkeypatch.setattr(requests, "post", fake_post)
    client = ElasticClient()
    assert client.resolve_host_from_ip("192.168.75.11") == "elk-siem"


def test_resolve_host_from_ip_returns_none_on_empty_ip():
    client = ElasticClient()
    assert client.resolve_host_from_ip("") is None
    assert client.resolve_host_from_ip(None) is None


def test_search_failure_returns_empty_list_not_exception(monkeypatch):
    """A transport-level failure (cluster down, timeout, auth error) must
    degrade to an empty hit list, never propagate as an exception -- this
    is what lets enrichment fields resolve to None instead of crashing
    the Fact-Finding Agent."""

    def fake_post(url, headers, json, timeout):
        raise requests.exceptions.ConnectionError("cluster unreachable")

    monkeypatch.setattr(requests, "post", fake_post)
    client = ElasticClient(host="http://dead-cluster:9200")

    assert client.get_process_creation_context(entity_id="guid-x") is None
    assert client.resolve_host_from_ip("10.0.0.1") is None


def test_api_key_included_in_headers_when_configured(monkeypatch):
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["headers"] = headers
        return _FakeResponse([])

    monkeypatch.setattr(requests, "post", fake_post)
    client = ElasticClient(api_key="secret-key")
    client.resolve_host_from_ip("1.2.3.4")

    assert captured["headers"]["Authorization"] == "ApiKey secret-key"
