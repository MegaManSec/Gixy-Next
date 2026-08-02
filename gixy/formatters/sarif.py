from __future__ import absolute_import

import json
import os

import gixy
from gixy.formatters.base import BaseFormatter

_SEVERITY_TO_LEVEL = {
    gixy.severity.HIGH: "error",
    gixy.severity.MEDIUM: "warning",
    gixy.severity.LOW: "note",
    gixy.severity.INFORMATION: "note",
}


def _to_uri(path):
    """Turn a filesystem path into a SARIF URI, repo-relative when possible."""
    try:
        rel = os.path.relpath(path)
    except ValueError:
        # Windows: path on a different drive than the working directory
        rel = path
    if not rel.startswith(os.pardir):
        path = rel
    return path.replace(os.sep, "/")


class SarifFormatter(BaseFormatter):
    """Formats reports as a SARIF 2.1.0 log, e.g. for GitHub code scanning."""

    def format_reports(self, reports, stats):
        rules = {}
        results = []

        for path, issues in reports.items():
            for issue in issues:
                rule_id = issue["plugin"]
                level = _SEVERITY_TO_LEVEL.get(issue["severity"], "warning")

                if rule_id not in rules:
                    rule = {
                        "id": rule_id,
                        "shortDescription": {"text": issue["summary"] or rule_id},
                        "fullDescription": {
                            "text": issue["description"] or issue["summary"] or rule_id
                        },
                        "defaultConfiguration": {"level": level},
                    }
                    if issue["help_url"]:
                        rule["helpUri"] = issue["help_url"]
                    rules[rule_id] = rule

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
                elif path and path != "-":
                    uri = path
                else:
                    uri = None

                if uri:
                    physical_location = {
                        "artifactLocation": {"uri": _to_uri(uri)},
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
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_log, indent=2)
