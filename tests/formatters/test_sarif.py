import io
import json

from gixy.core.context import purge_context
from gixy.core.manager import Manager
from gixy.formatters.sarif import SarifFormatter, _to_uri

SPLITTING_CONFIG = r"""
http {
server {
    location ~ /v1/((?<action>[^.]*)\.json)?$ {
        add_header X-Action $action;
    }
}
}
"""


def teardown_function():
    purge_context()


def _format(path, config):
    manager = Manager()
    manager.audit(path, io.StringIO(config), is_stdin=True)
    formatter = SarifFormatter()
    formatter.feed(path, manager)
    return json.loads(formatter.flush())


def test_sarif_log_structure():
    log = _format("/etc/nginx/nginx.conf", SPLITTING_CONFIG)

    assert log["version"] == "2.1.0"
    assert "sarif-schema-2.1.0" in log["$schema"]
    assert len(log["runs"]) == 1

    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Gixy-Next"
    assert driver["informationUri"] == "https://gixy.io/"

    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert rule_ids == sorted(rule_ids)
    assert "http_splitting" in rule_ids


def test_sarif_result_fields():
    log = _format("/etc/nginx/nginx.conf", SPLITTING_CONFIG)

    results = [
        r for r in log["runs"][0]["results"] if r["ruleId"] == "http_splitting"
    ]
    assert len(results) == 1
    result = results[0]

    assert result["level"] == "error"
    assert "$action" in result["message"]["text"]
    assert "add_header X-Action $action" in result["properties"]["config"]

    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "/etc/nginx/nginx.conf"
    assert location["region"]["startLine"] == 5

    rule = next(
        r for r in log["runs"][0]["tool"]["driver"]["rules"]
        if r["id"] == "http_splitting"
    )
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"] == "https://gixy.io/plugins/http_splitting/"
    assert rule["properties"]["security-severity"] == "8.0"


def test_stdin_results_have_no_location():
    # main.py audits stdin as "<stdin>" and feeds the formatter with "-";
    # neither is a valid SARIF artifact URI, so no location should be emitted
    manager = Manager()
    manager.audit("<stdin>", io.StringIO(SPLITTING_CONFIG), is_stdin=True)
    formatter = SarifFormatter()
    formatter.feed("-", manager)
    log = json.loads(formatter.flush())

    results = [
        r for r in log["runs"][0]["results"] if r["ruleId"] == "http_splitting"
    ]
    assert len(results) == 1
    assert "locations" not in results[0]


def test_no_issues_produces_empty_run():
    log = _format("/etc/nginx/nginx.conf", "worker_processes auto;\n")

    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


def test_to_uri_relativizes_paths_under_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(str(tmp_path))
    assert _to_uri(str(tmp_path / "conf.d" / "site.conf")) == "conf.d/site.conf"
    assert _to_uri("/somewhere/else/nginx.conf") == "/somewhere/else/nginx.conf"
