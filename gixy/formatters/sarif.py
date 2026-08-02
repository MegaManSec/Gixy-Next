from __future__ import absolute_import

import json
import os
from pathlib import Path

import gixy
from gixy.formatters.base import BaseFormatter

_SEVERITY_TO_LEVEL = {
    gixy.severity.HIGH: "error",
    gixy.severity.MEDIUM: "warning",
    gixy.severity.LOW: "note",
    gixy.severity.INFORMATION: "note",
}

# GitHub code scanning buckets "security-severity" scores as:
# >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, < 4.0 low.
_SEVERITY_TO_SCORE = {
    gixy.severity.HIGH: "8.0",
    gixy.severity.MEDIUM: "5.0",
    gixy.severity.LOW: "2.0",
}

_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(gixy.severity.ALL)}


def _upsert_rule(rules, rule_severities, issue):
    """Register the issue's rule, keeping its metadata at the highest severity.

    Plugins can emit issues at different severities under one rule id, and
    consumers like GitHub bucket every alert of a rule by its rule-level
    "security-severity".
    """
    rule_id = issue["plugin"]
    severity = issue["severity"]

    if rule_id not in rules:
        rule = {
            "id": rule_id,
            "shortDescription": {"text": issue["summary"] or rule_id},
            "fullDescription": {
                "text": issue["description"] or issue["summary"] or rule_id
            },
        }
        if issue["help_url"]:
            rule["helpUri"] = issue["help_url"]
        rules[rule_id] = rule

    if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(
        rule_severities.get(rule_id), -1
    ):
        rule = rules[rule_id]
        rule["defaultConfiguration"] = {
            "level": _SEVERITY_TO_LEVEL.get(severity, "warning")
        }
        score = _SEVERITY_TO_SCORE.get(severity)
        if score:
            rule["properties"] = {"security-severity": score}
        rule_severities[rule_id] = severity


def _artifact_location(path, base):
    """Build a SARIF artifactLocation for a filesystem path.

    Paths under the base directory become URIs relative to the SRCROOT
    base declared in the run's originalUriBaseIds; anything else gets an
    absolute file:// URI, so consumers never resolve a path against the
    wrong root.
    """
    abspath = os.path.abspath(path)
    try:
        rel = os.path.relpath(abspath, base)
    except ValueError:
        # Windows: path on a different drive than the base directory
        rel = None
    if rel is not None and rel != os.pardir and not rel.startswith(os.pardir + os.sep):
        return {"uri": rel.replace(os.sep, "/"), "uriBaseId": "SRCROOT"}
    return {"uri": Path(abspath).as_uri()}


class SarifFormatter(BaseFormatter):
    """Formats reports as a SARIF 2.1.0 log, e.g. for GitHub code scanning."""

    def format_reports(self, reports, stats):
        rules = {}
        rule_severities = {}
        results = []
        # The scan-time working directory anchors relative URIs; in CI this
        # is the checked-out workspace, which is what GitHub resolves against.
        base = os.getcwd()

        for path, issues in reports.items():
            for issue in issues:
                rule_id = issue["plugin"]
                level = _SEVERITY_TO_LEVEL.get(issue["severity"], "warning")
                _upsert_rule(rules, rule_severities, issue)

                result = {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": issue["reason"] or issue["summary"] or rule_id
                    },
                }

                if issue["config"]:
                    result["properties"] = {"config": issue["config"].strip("\n")}

                location = issue.get("location")
                if location and location.get("file"):
                    uri = location["file"]
                else:
                    uri = path
                if uri in (gixy.STDIN_ARG, gixy.STDIN_NAME):
                    uri = None

                if uri:
                    physical_location = {
                        "artifactLocation": _artifact_location(uri, base),
                    }
                    if location and location.get("line"):
                        physical_location["region"] = {"startLine": location["line"]}
                    result["locations"] = [{"physicalLocation": physical_location}]

                results.append(result)

        sarif_log = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Gixy-Next",
                            "informationUri": "https://gixy.io/",
                            "version": gixy.version,
                            "rules": sorted(rules.values(), key=lambda r: r["id"]),
                        }
                    },
                    # Base URIs must end with a slash per the SARIF spec
                    "originalUriBaseIds": {
                        "SRCROOT": {"uri": Path(base).as_uri() + "/"}
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_log, indent=2)
