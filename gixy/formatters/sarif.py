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
    """Turn a filesystem path into a SARIF-friendly (preferably repo-relative) URI."""
    try:
        rel = os.path.relpath(path)
    except ValueError:
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
                    rules[rule_id] = {
                        "id": rule_id,
                        "shortDescription": {"text": issue["summary"] or rule_id},
                        "fullDescription": {
                            "text": issue["description"]
                            or issue["summary"]
                            or rule_id
                        },
                        "helpUri": issue["help_url"] or "",
                        "defaultConfiguration": {"level": level},
                    }

                location = issue.get("location")
                if location and location.get("file"):
                    uri = location["file"]
                elif path and path not in ("<stdin>", "-"):
                    uri = path
                else:
                    uri = None

                result = {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": issue["summary"] or rule_id},
                }

                properties = {}
                if issue.get("reason"):
                    properties["reason"] = issue["reason"]
                if issue.get("config"):
                    properties["config"] = issue["config"].strip("\n")
                if properties:
                    result["properties"] = properties

                if uri:
                    physical_location = {
                        "artifactLocation": {"uri": _to_uri(uri)},
                    }
                    line = location.get("line") if location else None
                    if line:
                        physical_location["region"] = {"startLine": line}
                    result["locations"] = [{"physicalLocation": physical_location}]

                results.append(result)

        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Gixy-Next",
                            "informationUri": "https://github.com/dvershinin/gixy",
                            "version": gixy.version,
                            "rules": sorted(rules.values(), key=lambda r: r["id"]),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_log, indent=2, sort_keys=False)
