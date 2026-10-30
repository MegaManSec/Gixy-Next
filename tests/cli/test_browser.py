"""Exercise the Python bridge shipped in the browser scanner."""

import ast
import json
import logging
import re
import sys
from pathlib import Path

import pytest

import gixy.cli.main as cli
from gixy.plugins.resolver_external import resolver_external

ROOT = Path(__file__).parents[2]


def run_bridge(tmp_path, monkeypatch, config):
    path = tmp_path / "nginx.conf"
    path.write_text(config)
    source = (ROOT / "docs/extra/gixy-scan.js").read_text()
    bridge = source.split("const out = await py.runPythonAsync(`", 1)[1].split("`);", 1)[0]
    bridge = bridge.replace("${inputPath}", str(path))
    parsed = ast.parse(bridge)
    expression = ast.Expression(parsed.body.pop().value)
    namespace = {}
    monkeypatch.setattr(sys, "argv", [])
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    exec(compile(parsed, "<browser>", "exec"), namespace)
    return json.loads(eval(compile(expression, "<browser>", "eval"), namespace))


@pytest.mark.parametrize("config,exit_code,findings,kinds", [
    ("worker_processes auto;", 0, False, []),
    ("resolver 8.8.8.8;", 1, True, []),
    ("server {", 2, False, ["malformed"]),
    ("add_header X;", 2, False, ["malformed"]),
    ("resolver 8.8.8.8;\nadd_header X;", 2, True, ["malformed"]),
])
def test_browser_preserves_cli_outcome(tmp_path, monkeypatch, config, exit_code, findings, kinds):
    emit = cli._emit_diagnostics
    outcome = run_bridge(tmp_path, monkeypatch, config)
    assert outcome["exit_code"] == exit_code
    assert bool(json.loads(outcome["report"])) == findings
    assert [problem["kind"] for problem in outcome["problems"]] == kinds
    assert cli._emit_diagnostics is emit
    if exit_code == 2:
        assert "could not fully analyze" in outcome["diagnostics"]


def test_browser_describes_problems(tmp_path, monkeypatch):
    outcome = run_bridge(tmp_path, monkeypatch, "add_header X;")
    assert outcome["problems"] == [{
        "kind": "malformed",
        "message": "Directive 'add_header' is missing one or more required arguments.",
        "file": str(tmp_path / "nginx.conf"),
        "line": 1,
        "directive": "add_header",
        "plugin": None,
    }]


def test_browser_reports_internal_errors(tmp_path, monkeypatch):
    def broken(self, directive):
        raise RuntimeError("boom")

    monkeypatch.setattr(resolver_external, "audit", broken)
    outcome = run_bridge(tmp_path, monkeypatch, "resolver 8.8.8.8;")
    assert outcome["exit_code"] == 3
    assert [(p["kind"], p["plugin"], p["message"]) for p in outcome["problems"]] == [
        ("internal", "resolver_external", "RuntimeError: boom"),
    ]


def test_browser_pins_match_requirements():
    source = (ROOT / "docs/extra/gixy-scan.js").read_text()
    pins = re.findall(r'"([^"]+==[^"]+)"', source.split("const PYPI_PINS = [", 1)[1].split("];", 1)[0])
    locked = set(re.findall(r"^\S+==\S+", (ROOT / "requirements.txt").read_text(), re.M))
    assert pins
    assert set(pins) <= locked
