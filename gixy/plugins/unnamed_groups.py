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
        "This check flags a specific pattern associated with CVE-2026-42945: a rewrite "
        "replacement that contains both a query string ('?') and numeric capture group "
        "references ($1, $2, …). Not all uses of unnamed capture groups are flagged — "
        "only this combination. The underlying bug is in nginx itself; if you are running "
        "a patched version (1.30.1+/1.31.0+, or NGINX Plus R32 P6+/R36 P4+), no action "
        "is required. On unpatched versions, switching to named capture groups avoids the "
        "vulnerable pattern and improves readability."
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
