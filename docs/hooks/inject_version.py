"""MkDocs hook: expose the gixy package version to templates.

Reads the version from gixy/__init__.py (same source as setup.py) and
stores it in config.extra so docs/overrides/main.html can emit an exact
softwareVersion in the JSON-LD instead of a hardcoded, stale value.
"""

import re
from pathlib import Path


def on_config(config):
    init_py = Path(config.config_file_path).parent / "gixy" / "__init__.py"
    match = re.search(
        r'^version\s*=\s*[\'"]([^\'"]*)[\'"]',
        init_py.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not match:
        raise RuntimeError("Cannot find version information in gixy/__init__.py")
    config.extra["gixy_version"] = match.group(1)
    return config
