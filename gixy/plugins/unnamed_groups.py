import re

import gixy
from gixy.plugins.plugin import Plugin


class unnamed_groups(Plugin):
    r"""
    Detects rewrite directives that combine a query string ('?') in the
    replacement URL with numeric capture group references ($1, $2, …) anywhere
    in that replacement — the pattern exploited by CVE-2026-42945 ("nginx rift").

    The bug is a heap buffer overflow in ngx_http_rewrite_module: the length
    calculation for capture group values uses the raw byte count, but the copy
    applies NGX_ESCAPE_ARGS escaping (triggered by the presence of '?'), so
    characters like '%', '+', and '&' expand from 1 to 3 bytes and overflow the
    buffer. The overflow affects ALL $N references in the replacement, including
    those that appear before the '?'.

    Whether any given nginx build is exploitable depends entirely on the nginx
    version and patch status, which cannot be determined from a config file.
    This finding is therefore informational: switching to named capture groups
    is the recommended fix and also improves readability independent of the CVE.

    Flagged ($N after ?):
        rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;

    Also flagged ($N before ?):
        rewrite ^/(.*)$ /$1?v=2 last;

    Preferred (named captures):
        rewrite ^/users/(?<id>[0-9]+)/profile/(?<tab>.*)$ /profile.php?id=$id&tab=$tab last;
    """

    summary = "Unnamed capture group reference in rewrite with query string (CVE-2026-42945)."
    severity = gixy.severity.INFORMATION
    description = (
        "When a rewrite replacement contains '?' (triggering query-string escaping), "
        "any numeric capture group reference ($1, $2, …) anywhere in that replacement "
        "is subject to CVE-2026-42945 ('nginx rift') — a heap buffer overflow. "
        "Whether the instance is exploitable depends on the nginx version and patch "
        "status, which is not visible in the config. Switching to named capture groups "
        "is the recommended mitigation and also improves readability."
    )
    help_url = "https://gixy.io/plugins/unnamed_groups/"
    directives = ["rewrite"]

    _CAPTURE_GROUP_REF = re.compile(r"\$([1-9]\d*)")

    def audit(self, directive):
        if len(directive.args) < 2:
            return

        replacement = directive.args[1]
        if "?" not in replacement:
            return

        capture_refs = self._CAPTURE_GROUP_REF.findall(replacement)
        if not capture_refs:
            return

        refs = ", ".join(f"${ref}" for ref in capture_refs)
        self.add_issue(
            directive=directive,
            reason=(
                f"Rewrite replacement contains '?' and references numeric capture "
                f"group(s) {refs}. See CVE-2026-42945."
            ),
        )
