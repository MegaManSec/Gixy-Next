"""Exercise the Python bridge shipped in the browser scanner."""

import ast
import json
import logging
from pathlib import Path

import pytest


@pytest.mark.parametrize("config,exit_code,findings", [
    ("worker_processes auto;", 0, False),
    ("resolver 8.8.8.8;", 1, True),
    ("server {", 2, False),
    ("add_header X;", 2, False),
    ("resolver 8.8.8.8;\nadd_header X;", 2, True),
])
def test_browser_preserves_cli_outcome(tmp_path, monkeypatch, config, exit_code, findings):
    import sys

    path = tmp_path / "nginx.conf"
    path.write_text(config)
    source = (Path(__file__).parents[2] / "docs/extra/gixy-scan.js").read_text()
    bridge = source.split("const out = await py.runPythonAsync(`", 1)[1].split("`);", 1)[0]
    bridge = bridge.replace("${inputPath}", str(path))
    parsed = ast.parse(bridge)
    expression = ast.Expression(parsed.body.pop().value)
    namespace = {}
    monkeypatch.setattr(sys, "argv", [])
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    exec(compile(parsed, "<browser>", "exec"), namespace)
    outcome = json.loads(eval(compile(expression, "<browser>", "eval"), namespace))
    assert outcome["exit_code"] == exit_code
    assert bool(json.loads(outcome["report"])) == findings
    if exit_code == 2:
        assert "could not fully analyze" in outcome["diagnostics"]
