import io
import json

import gixy
from gixy.core.context import purge_context
from gixy.core.manager import Manager
from gixy.formatters.sarif import SarifFormatter, _artifact_location

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

    srcroot = log["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"]
    assert srcroot.startswith("file://")
    assert srcroot.endswith("/")


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
    # /etc/nginx is outside the working directory, so the URI stays absolute
    assert location["artifactLocation"]["uri"] == "file:///etc/nginx/nginx.conf"
    assert location["region"]["startLine"] == 5

    rule = next(
        r for r in log["runs"][0]["tool"]["driver"]["rules"]
        if r["id"] == "http_splitting"
    )
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"] == "https://gixy.io/plugins/http_splitting/"
    assert rule["properties"]["security-severity"] == "8.0"


def test_rule_metadata_uses_highest_issue_severity():
    # Plugins like alias_traversal emit per-issue severities; the rule's
    # defaultConfiguration/security-severity must reflect the highest one,
    # not whichever issue happened to be walked first
    def issue(severity):
        return {
            "plugin": "alias_traversal",
            "summary": "Path traversal via misconfigured alias.",
            "severity": severity,
            "description": "",
            "help_url": "https://gixy.io/plugins/alias_traversal/",
            "reason": "",
            "config": "",
            "location": None,
        }

    formatter = SarifFormatter()
    log = json.loads(
        formatter.format_reports(
            {
                "/etc/nginx/nginx.conf": [
                    issue(gixy.severity.MEDIUM),
                    issue(gixy.severity.HIGH),
                ]
            },
            {},
        )
    )

    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "8.0"
    # Result levels still follow each issue's own severity
    assert [r["level"] for r in log["runs"][0]["results"]] == ["warning", "error"]


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


def test_artifact_location_anchors_paths_under_base_to_srcroot(tmp_path):
    base = str(tmp_path)

    assert _artifact_location(str(tmp_path / "conf.d" / "site.conf"), base) == {
        "uri": "conf.d/site.conf",
        "uriBaseId": "SRCROOT",
    }
    # A file whose name merely starts with ".." is still under the base
    assert _artifact_location(str(tmp_path / "..weird.conf"), base) == {
        "uri": "..weird.conf",
        "uriBaseId": "SRCROOT",
    }
    # Paths outside the base get an absolute file:// URI
    assert _artifact_location("/somewhere/else/nginx.conf", base) == {
        "uri": "file:///somewhere/else/nginx.conf"
    }
