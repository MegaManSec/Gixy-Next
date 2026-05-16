import re

import gixy
from gixy.plugins.plugin import Plugin


class unnamed_groups(Plugin):
    r"""
    Detects rewrite directives that reference numeric capture groups ($1, $2, …)
    in the query-string portion of the replacement URL — the pattern associated
    with CVE-2026-42945 ("nginx rift").

    Whether any given nginx build is exploitable depends entirely on the nginx
    version and patch status, which cannot be determined from a config file.
    This finding is therefore informational: switching to named capture groups
    is the recommended fix and also improves readability independent of the CVE.

    Flagged:
        rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;

    Preferred:
        rewrite ^/users/(?<id>[0-9]+)/profile/(?<tab>.*)$ /profile.php?id=$id&tab=$tab last;
    """

    summary = "Numeric capture group reference in rewrite query string (CVE-2026-42945)."
    severity = gixy.severity.INFORMATION
    description = (
        "Referencing numeric capture groups ($1, $2, …) after a '?' in a rewrite "
        "replacement is the pattern targeted by CVE-2026-42945 ('nginx rift'). "
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

        query_string = replacement.split("?", 1)[1]
        capture_refs = self._CAPTURE_GROUP_REF.findall(query_string)
        if not capture_refs:
            return

        refs = ", ".join(f"${ref}" for ref in capture_refs)
        self.add_issue(
            directive=directive,
            reason=(
                f"Rewrite target uses numeric capture group(s) {refs} in the query "
                "string. See CVE-2026-42945."
            ),
        )
