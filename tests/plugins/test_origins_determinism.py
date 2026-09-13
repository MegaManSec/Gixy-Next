"""Origins reports the same text on every run.

The examples in an `origins` finding come from a set, and Python randomises
string hashes per process, so joining the set directly made the reason text
vary between runs. That cannot be caught in-process — the seed is fixed once
the interpreter starts — so these tests run gixy in subprocesses under
different PYTHONHASHSEED values.
"""

import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONFIG = (
    "http {\n"
    "  server {\n"
    "    if ($http_origin ~* '(https?://(.*\\.)?(example\\.com|webvisor\\.com))') {\n"
    '      add_header Access-Control-Allow-Origin "$http_origin";\n'
    "    }\n"
    "  }\n"
    "}\n"
)

SEEDS = ["0", "1", "42", "12345"]


def _run(conf_path, seed):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIXY_")}
    env["PYTHONPATH"] = REPO_ROOT
    env["PYTHONHASHSEED"] = seed
    result = subprocess.run(
        [sys.executable, "-m", "gixy.cli.main", "-f", "text", conf_path],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    return result.stdout


@pytest.fixture
def conf(tmp_path):
    path = tmp_path / "origins.conf"
    path.write_text(CONFIG)
    return str(path)


def test_report_is_identical_across_hash_seeds(conf):
    outputs = {seed: _run(conf, seed) for seed in SEEDS}
    assert "origins" in outputs[SEEDS[0]]
    assert len(set(outputs.values())) == 1, [
        (seed, out) for seed, out in outputs.items() if out != outputs[SEEDS[0]]
    ]


def test_examples_are_listed_in_sorted_order(conf):
    out = _run(conf, SEEDS[0])
    match = re.search(r"Regex matches insecure `([^`]+)`", out)
    assert match, out
    examples = match.group(1).split(", ")
    assert len(examples) > 1
    assert examples == sorted(examples)
