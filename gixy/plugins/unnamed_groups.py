import re

import gixy
from gixy.plugins.plugin import Plugin


class unnamed_groups(Plugin):
    r"""
    Insecure examples:
        rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;
        rewrite ^/(.*)$ /$1?v=2 last;
    """

    summary = "Unnamed capture group reference in rewrite with query string (CVE-2026-42945)."
    severity = gixy.severity.INFORMATION
    description = (
        "Using numeric capture groups ($1, $2, …) in a rewrite replacement that "
        "contains a query string ('?') is associated with CVE-2026-42945 — a bug in "
        "nginx itself, fixed by updating nginx. Switching to named capture groups "
        "avoids the pattern on unpatched versions and improves readability."
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
