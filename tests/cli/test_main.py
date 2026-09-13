"""The CLI exit-code contract.

    0  clean, nothing found
    1  issues found
    2  invalid / unparsable nginx config
    3  internal error (a likely Gixy-Next bug)

Codes 2 and 3 deliberately differ: gixy is a security linter, not a syntax
checker, so bad input must not be reported as a gixy failure — and a real gixy
failure must not be silently swallowed as bad input.
"""

import os
import subprocess
import sys

import pytest

from gixy.cli.main import (
    EXIT_FINDINGS,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_CONFIG,
    EXIT_OK,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CLEAN = (
    "worker_processes auto;\n"
    "worker_rlimit_nofile 4096;\n"
    "events { worker_connections 1024; }\n"
    "http { server_tokens off; server { listen 80; } }\n"
)
WITH_FINDING = "http { server { location / { proxy_pass http://$http_host; } } }\n"
MISSING_ARG = "http { server { location / { add_header; } } }\n"
UNPARSABLE = "http { server { listen 80;\n"


@pytest.fixture
def conf(tmp_path):
    def write(content, name="nginx.conf"):
        path = tmp_path / name
        path.write_text(content)
        return str(path)

    return write


def run(*args, **kwargs):
    """Run the CLI the way a caller does, in a subprocess, so the exit code and
    the stdout/stderr split are the real ones."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIXY_")}
    env["PYTHONPATH"] = REPO_ROOT
    return subprocess.run(
        [sys.executable, "-m", "gixy.cli.main", "-f", "text"] + list(args),
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        **kwargs
    )


# ---------------------------------------------------------------------------
# The four outcomes
# ---------------------------------------------------------------------------

def test_clean_config_exits_zero(conf):
    result = run(conf(CLEAN))
    assert result.returncode == EXIT_OK
    assert "could not fully analyze" not in result.stderr
    assert "internal error" not in result.stderr


def test_findings_exit_one(conf):
    result = run(conf(WITH_FINDING))
    assert result.returncode == EXIT_FINDINGS
    assert "ssrf" in result.stdout


def test_malformed_directive_exits_two(conf):
    result = run(conf(MISSING_ARG))
    assert result.returncode == EXIT_INVALID_CONFIG
    assert "could not fully analyze" in result.stderr
    assert "add_header" in result.stderr


def test_unparsable_config_exits_two(conf):
    result = run(conf(UNPARSABLE))
    assert result.returncode == EXIT_INVALID_CONFIG
    assert "could not fully analyze" in result.stderr


def test_missing_file_exits_one():
    result = run("/nonexistent/nginx.conf")
    assert result.returncode == 1
    assert "was not found" in result.stderr


# ---------------------------------------------------------------------------
# Framing: bad input is not reported as a gixy bug, and vice versa
# ---------------------------------------------------------------------------

def test_malformed_input_is_not_blamed_on_gixy(conf):
    result = run(conf(MISSING_ARG))
    assert "not a configuration validator" in result.stderr
    assert "nginx -t" in result.stderr
    assert "bug in gixy" not in result.stderr
    assert "Traceback" not in result.stderr


def test_no_traceback_escapes_to_the_user(conf):
    for content in (MISSING_ARG, UNPARSABLE, "include;\n", "proxy_pass ;\n"):
        result = run(conf(content))
        assert "Traceback" not in result.stderr, content
        assert result.returncode in (EXIT_OK, EXIT_FINDINGS, EXIT_INVALID_CONFIG)


def test_report_on_stdout_diagnostics_on_stderr(conf):
    result = run(conf(MISSING_ARG))
    assert "Summary" in result.stdout
    assert "could not fully analyze" not in result.stdout
    assert "Summary" not in result.stderr


def test_diagnostics_still_emitted_when_report_goes_to_a_file(conf, tmp_path):
    out = tmp_path / "report.txt"
    result = run("-o", str(out), conf(MISSING_ARG))
    assert result.returncode == EXIT_INVALID_CONFIG
    assert "could not fully analyze" in result.stderr
    assert "Summary" in out.read_text()


# ---------------------------------------------------------------------------
# Precedence and de-duplication
# ---------------------------------------------------------------------------

def test_worst_outcome_wins_across_files(conf):
    result = run(conf(WITH_FINDING, "a.conf"), conf(MISSING_ARG, "b.conf"))
    assert result.returncode == EXIT_INVALID_CONFIG


def test_findings_outrank_a_clean_file(conf):
    result = run(conf(CLEAN, "a.conf"), conf(WITH_FINDING, "b.conf"))
    assert result.returncode == EXIT_FINDINGS


def test_identical_diagnostics_are_reported_once(conf):
    """Several plugins can hit the same missing argument independently."""
    result = run(conf("http { server { location / { proxy_pass ; } } }\n"))
    assert result.stderr.count("could not fully analyze") == 1


# ---------------------------------------------------------------------------
# Help text documents the contract
# ---------------------------------------------------------------------------

def test_help_documents_exit_codes():
    result = run("--help")
    assert "exit codes" in result.stdout
    assert "2 = invalid" in result.stdout


# ---------------------------------------------------------------------------
# Internal errors: exit 3, issue tracker, traceback only under --debug
# ---------------------------------------------------------------------------

def _run_in_process(monkeypatch, capsys, argv):
    from gixy.cli import main as cli

    monkeypatch.setattr(sys, "argv", ["gixy", "-f", "text"] + argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code, capsys.readouterr()


def test_unexpected_failure_exits_three(monkeypatch, capsys, conf):
    from gixy.core.manager import Manager

    def boom(self, *args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(Manager, "audit", boom)
    code, captured = _run_in_process(monkeypatch, capsys, [conf(CLEAN)])

    assert code == EXIT_INTERNAL_ERROR
    assert "internal error analyzing" in captured.err
    assert "RuntimeError: kaboom" in captured.err
    assert "bug in gixy" in captured.err
    assert "issues" in captured.err
    assert "Traceback" not in captured.err


def test_debug_shows_the_traceback(monkeypatch, capsys, conf):
    from gixy.core.manager import Manager

    def boom(self, *args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(Manager, "audit", boom)
    code, captured = _run_in_process(monkeypatch, capsys, ["-d", conf(CLEAN)])

    assert code == EXIT_INTERNAL_ERROR
    assert "Traceback" in captured.err
    assert "re-run with --debug" not in captured.err


def test_internal_error_outranks_findings(monkeypatch, capsys, conf):
    from gixy.core.plugins_manager import PluginsManager

    original = PluginsManager._run_plugin_safely

    def explode(_):
        raise RuntimeError("kaboom")

    def boom(self, plugin, hook, arg, directive):
        if plugin.name == "ssrf":
            hook = explode
        return original(self, plugin, hook, arg, directive)

    monkeypatch.setattr(PluginsManager, "_run_plugin_safely", boom)
    code, captured = _run_in_process(monkeypatch, capsys, [conf(WITH_FINDING)])

    assert code == EXIT_INTERNAL_ERROR
    assert "in plugin 'ssrf'" in captured.err
