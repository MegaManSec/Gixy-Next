import json
import os
import subprocess
import sys

from gixy.cli.main import _collect_nginx_configs, _select_entry_points

VULN_SERVER = (
    "server {\n"
    "    location ~ /v1/((?<action>[^.]*)\\.json)?$ {\n"
    "        add_header X-Action $action;\n"
    "    }\n"
    "}\n"
)


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def _touch(path):
    _write(path, "# test\n")


def _run_gixy(*args):
    return subprocess.run(
        [sys.executable, "-m", "gixy", *args, "-f", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _splitting_issues(proc):
    return [
        i
        for i in json.loads(proc.stdout.decode("utf-8"))
        if i["plugin"] == "http_splitting"
    ]


def test_collects_conf_files_recursively_shallowest_first(tmp_path):
    root = str(tmp_path)
    _touch(os.path.join(root, "nginx.conf"))
    _touch(os.path.join(root, "conf.d", "site.conf"))
    _touch(os.path.join(root, "sites-available", "example.conf"))

    found = _collect_nginx_configs(root)

    # Shallower configs come first so entry points like nginx.conf lead
    # the report
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
    _write(os.path.join(root, "conf.d", "vuln.conf"), VULN_SERVER)

    issues = _splitting_issues(_run_gixy(root))

    # vuln.conf is covered by nginx.conf's include, so it must not
    # additionally be audited standalone
    assert len(issues) == 1
    assert issues[0]["path"].endswith("nginx.conf")
    assert issues[0]["file"].endswith("vuln.conf")


def test_includer_sorted_after_its_fragment_still_covers_it(tmp_path):
    # zzz.conf includes aaa.conf: even though the fragment sorts first,
    # it must only be reported through its includer
    root = str(tmp_path)
    _write(os.path.join(root, "aaa.conf"), VULN_SERVER)
    _write(os.path.join(root, "zzz.conf"), "http {\n    include aaa.conf;\n}\n")

    issues = _splitting_issues(_run_gixy(root))

    assert len(issues) == 1
    assert issues[0]["path"].endswith("zzz.conf")


def test_include_only_wrapper_is_not_audited_standalone(tmp_path):
    # wrapper.conf contributes no directives of its own, only an include;
    # it still must not be re-audited standalone
    root = str(tmp_path)
    _write(os.path.join(root, "nginx.conf"), "http {\n    include wrapper.conf;\n}\n")
    _write(os.path.join(root, "wrapper.conf"), "include conf.d/real.conf;\n")
    _write(os.path.join(root, "conf.d", "real.conf"), VULN_SERVER)

    issues = _splitting_issues(_run_gixy(root))

    assert len(issues) == 1
    assert issues[0]["path"].endswith("nginx.conf")


def test_config_dump_does_not_suppress_live_configs(tmp_path):
    # An nginx -T dump resolves includes against its own records, so it must
    # not claim the live files its records happen to be named after
    root = str(tmp_path)
    live = os.path.join(root, "conf.d", "site.conf")
    _write(live, VULN_SERVER)
    _write(
        os.path.join(root, "dump.conf"),
        "# configuration file {root}/live-nginx.conf:\n"
        "http {{\n"
        "    include {root}/conf.d/*.conf;\n"
        "}}\n"
        "# configuration file {live}:\n"
        "{vuln}".format(root=root, live=live, vuln=VULN_SERVER),
    )

    issues = _splitting_issues(_run_gixy(root))

    # One finding through the dump, and one from the live file itself
    assert sorted(i["path"] for i in issues) == [
        live,
        os.path.join(root, "dump.conf"),
    ]


def test_explicit_file_is_audited_even_when_a_scanned_directory_covers_it(tmp_path):
    root = str(tmp_path)
    site = os.path.join(root, "conf.d", "site.conf")
    _write(os.path.join(root, "nginx.conf"), "http {\n    include conf.d/*.conf;\n}\n")
    _write(site, VULN_SERVER)

    issues = _splitting_issues(_run_gixy(root, site))

    # Once in nginx.conf's context, once standalone as explicitly requested
    assert sorted(i["path"] for i in issues) == [
        site,
        os.path.join(root, "nginx.conf"),
    ]


def test_overlapping_directory_arguments_audit_files_once(tmp_path):
    root = str(tmp_path)
    sub = os.path.join(root, "sub")
    _write(os.path.join(sub, "vuln.conf"), VULN_SERVER)

    issues = _splitting_issues(_run_gixy(root, sub))

    assert len(issues) == 1


def test_foreign_conf_files_do_not_fail_the_scan(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "nginx.conf"), "worker_processes auto;\n")
    _write(os.path.join(root, "supervisord.conf"), "[program:x]\ncommand=/bin/true\n")

    proc = _run_gixy(root)

    assert proc.returncode == 0
    assert json.loads(proc.stdout.decode("utf-8")) == []
    assert "supervisord.conf" in proc.stderr.decode("utf-8")


def test_foreign_conf_files_are_skipped_with_disabled_includes(tmp_path):
    root = str(tmp_path)
    _write(os.path.join(root, "nginx.conf"), "worker_processes auto;\n")
    _write(os.path.join(root, "supervisord.conf"), "[program:x]\ncommand=/bin/true\n")

    proc = _run_gixy(root, "--disable-includes")

    assert proc.returncode == 0
    assert json.loads(proc.stdout.decode("utf-8")) == []


def test_empty_directory_argument_does_not_abort_the_run(tmp_path):
    root = str(tmp_path)
    empty = os.path.join(root, "empty")
    os.makedirs(empty)
    scanned = os.path.join(root, "scanned")
    _write(os.path.join(scanned, "vuln.conf"), VULN_SERVER)

    proc = _run_gixy(empty, scanned)

    assert len(_splitting_issues(proc)) == 1
    assert "empty" in proc.stderr.decode("utf-8")


def test_only_empty_directories_exit_nonzero(tmp_path):
    empty = os.path.join(str(tmp_path), "empty")
    os.makedirs(empty)

    proc = _run_gixy(empty)

    assert proc.returncode == 1
    assert "Nothing to audit" in proc.stderr.decode("utf-8")


def test_select_entry_points_drops_included_configs(tmp_path):
    root = str(tmp_path)
    fragment = os.path.join(root, "aaa.conf")
    includer = os.path.join(root, "zzz.conf")
    _write(fragment, VULN_SERVER)
    _write(includer, "http {\n    include aaa.conf;\n}\n")

    assert _select_entry_points({fragment, includer}, True) == {includer}
    # Without include processing every file stands alone
    assert _select_entry_points({fragment, includer}, False) == {fragment, includer}


def test_select_entry_points_keeps_include_cycles_auditable(tmp_path):
    root = str(tmp_path)
    a = os.path.join(root, "a.conf")
    b = os.path.join(root, "b.conf")
    _write(a, "include b.conf;\n")
    _write(b, "include a.conf;\n")

    assert _select_entry_points({a, b}, True) == {a, b}
