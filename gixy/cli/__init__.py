"""Exit codes shared by the CLI and its argument parser.

Kept here rather than in `main` so `argparser` can use them without an
import cycle.
"""

EXIT_OK = 0  # parsed and audited cleanly, no issues found
EXIT_FINDINGS = 1  # one or more issues were reported
EXIT_INVALID_CONFIG = 2  # input is not valid nginx; could not be fully analyzed
EXIT_INTERNAL_ERROR = 3  # an unexpected error in Gixy-Next (likely a bug)
EXIT_USAGE = 4  # gixy was invoked incorrectly
