# flake8: noqa

import warnings

# urllib3 (pulled in transitively via tldextract -> requests, used by some
# plugins) warns at import time when Python's ssl module isn't linked against
# OpenSSL, e.g. macOS's system Python linked against LibreSSL. This is
# unrelated to gixy's own behavior, so silence it before anything imports
# urllib3.
warnings.filterwarnings(
    "ignore", message=r"urllib3 v2 only supports OpenSSL 1\.1\.1\+.*"
)

from gixy.core import severity

version = "0.5.0"
