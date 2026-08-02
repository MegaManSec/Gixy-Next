import json
import os
import subprocess
import sys

from gixy.cli.main import _collect_nginx_configs


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def _touch(path):
    _write(path, "# test\n")


def test_collects_conf_files_recursively_shallowest_first(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "nginx.conf"))
    _touch(os.path.join(root, "conf.d", "site.conf"))
    _touch(os.path.join(root, "sites-available", "example.conf"))

    found = _collect_nginx_configs(root)

    # Shallower configs come first so entry points are audited before
    # the fragments they include
    assert found == [
        os.path.join(root, "nginx.conf"),
        os.path.join(root, "conf.d", "site.conf"),
        os.path.join(root, "sites-available", "example.conf"),
    ]


def test_matches_conf_extension_case_insensitively(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "UPPER.CONF"))

    assert _collect_nginx_configs(root) == [os.path.join(root, "UPPER.CONF")]


def test_ignores_non_conf_files(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "README.md"))
    _touch(os.path.join(root, "nginx.conf.bak"))

    assert _collect_nginx_configs(root) == []


def test_follows_directory_symlinks(tmp_path):
    root = str(tmp_path)
    outside = str(tmp_path.parent / (tmp_path.name + "-outside"))
    _touch(os.path.join(outside, "linked.conf"))
    os.symlink(outside, os.path.join(root, "linked"))

    assert _collect_nginx_configs(root) == [
        os.path.join(root, "linked", "linked.conf")
    ]


def test_symlink_cycle_does_not_hang(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "sub", "site.conf"))
    os.symlink(root, os.path.join(root, "sub", "loop"))

    assert _collect_nginx_configs(root) == [os.path.join(root, "sub", "site.conf")]


def test_deduplicates_file_symlinks(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "sites-available", "example.conf"))
    os.makedirs(os.path.join(root, "sites-enabled"))
    os.symlink(
        os.path.join(root, "sites-available", "example.conf"),
        os.path.join(root, "sites-enabled", "example.conf"),
    )

    assert _collect_nginx_configs(root) == [
        os.path.join(root, "sites-available", "example.conf")
    ]


def test_skips_vcs_dependency_and_hidden_directories(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "nginx.conf"))
    for skipped in (".git", ".hg", ".svn", "node_modules", "__pycache__", ".hidden"):
        _touch(os.path.join(root, skipped, "ignored.conf"))

    assert _collect_nginx_configs(root) == [os.path.join(root, "nginx.conf")]


def test_directory_scan_reports_included_files_only_once(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "nginx.conf"), "http {\n    include conf.d/*.conf;\n}\n")
    _write(
        os.path.join(root, "conf.d", "vuln.conf"),
        "server {\n"
        "    location ~ /v1/((?<action>[^.]*)\\.json)?$ {\n"
        "        add_header X-Action $action;\n"
        "    }\n"
        "}\n",
    )

    proc = subprocess.run(
        [sys.executable, "-m", "gixy", root, "-f", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    issues = [
        i
        for i in json.loads(proc.stdout.decode("utf-8"))
        if i["plugin"] == "http_splitting"
    ]

    # vuln.conf is covered by nginx.conf's include, so it must not
    # additionally be audited standalone
    assert len(issues) == 1
    assert issues[0]["path"].endswith("nginx.conf")
    assert issues[0]["file"].endswith("vuln.conf")
