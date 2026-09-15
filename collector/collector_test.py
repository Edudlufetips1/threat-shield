from types import SimpleNamespace

import collector


def test_fetch_kev_feed_returns_json(monkeypatch):
    expected_data = {"vulnerabilities": [{"cveID": "CVE-2023-1234"}]}

    def fake_get(url):
        assert url == collector.KEV_URL
        return SimpleNamespace(status_code=200, json=lambda: expected_data)

    monkeypatch.setattr(collector.requests, "get", fake_get)

    result = collector.fetch_kev_feed(collector.KEV_URL)

    assert result == expected_data


def test_fetch_kev_feed_rejects_failed_response(monkeypatch):
    response = SimpleNamespace(status_code=503)
    monkeypatch.setattr(collector.requests, "get", lambda url: response)

    try:
        collector.fetch_kev_feed(collector.KEV_URL)
    except ValueError as error:
        assert "503" in str(error)
    else:
        raise AssertionError("fetch_kev_feed should reject a failed response")


def test_normalize_item_maps_cisa_fields():
    raw_vulnerability = {
        "cveID": "CVE-2023-1234",
        "vulnerabilityName": "Example Remote Code Execution",
        "shortDescription": "Example description",
        "dateAdded": "2023-01-01",
        "knownRansomwareCampaignUse": "Known",
        "dueDate": "2023-02-01",
    }

    result = collector.normalize_item(raw_vulnerability)

    assert result == {
        "id": "CVE-2023-1234",
        "title": "Example Remote Code Execution",
        "description": "Example description",
        "source": "cisa_kev",
        "date": "2023-01-01",
        "ransomware_use": "Known",
        "due_date": "2023-02-01",
    }


def test_process_kev_feed_normalizes_each_vulnerability():
    feed = {
        "vulnerabilities": [
            {"cveID": "CVE-2023-1234", "vulnerabilityName": "First"},
            {"cveID": "CVE-2023-5678", "vulnerabilityName": "Second"},
        ]
    }

    result = collector.process_kev_feed(feed)

    assert [item["id"] for item in result] == [
        "CVE-2023-1234",
        "CVE-2023-5678",
    ]


def test_send_vulnerabilities_to_go_posts_json(monkeypatch):
    vulnerabilities = [{"id": "CVE-2023-1234"}]
    captured_request = {}

    def fake_post(url, json):
        captured_request["url"] = url
        captured_request["json"] = json
        return SimpleNamespace(status_code=202)

    monkeypatch.setattr(collector.requests, "post", fake_post)

    collector.send_vulnerabilities_to_go(vulnerabilities)

    assert captured_request == {
        "url": collector.GO_SERVER_URL,
        "json": vulnerabilities,
    }