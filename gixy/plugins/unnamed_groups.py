import re

import gixy
from gixy.plugins.plugin import Plugin


class unnamed_groups(Plugin):
    """
    Detects rewrite groups vulnerable to CVE-2026-42945

    rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;

    Directives like this where there is an unnamed group referenced after a "?"
    in the target are vulnerable.
    """

    summary = "Using numeric regex capture groups in a rewrite query string."
    severity = gixy.severity.MEDIUM
    description = (
        "Referencing numeric capture groups (like $1, $2) after a ? in a rewrite "
        "target can expose rewrite handling issues."
    )
    help_url = "https://gixy.io/plugins/unnamed_groups/"
    directives = ["rewrite"]

    CAPTURE_GROUP_REF = re.compile(r"\$([1-9]\d*)")

    def audit(self, directive):
        if directive.name == "rewrite":
            self._audit_rewrite(directive)

    def _audit_rewrite(self, directive):
        if len(directive.args) < 2:
            return

        replacement = directive.args[1]
        if "?" not in replacement:
            return

        query_string = replacement.split("?", 1)[1]
        capture_refs = self.CAPTURE_GROUP_REF.findall(query_string)
        if not capture_refs:
            return

        refs = ", ".join(f"${ref}" for ref in capture_refs)
        reason = (
            f"The rewrite target references numeric capture group(s) {refs} "
            "after a ? in the replacement URL."
        )
        self.add_issue(directive=directive, reason=reason)
