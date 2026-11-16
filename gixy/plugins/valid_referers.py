import re

import gixy
from gixy.core.regexp import PARSE_ERRORS, Regexp, RegexpTooComplex
from gixy.plugins.plugin import Plugin


def _is_open_regex(pattern):
    """True if `pattern`, matched against the Referer after its scheme, is not pinned to the start of
    that text or does not pin where the host name ends, so a Referer from another site can match it."""
    try:
        regexp = Regexp(pattern, case_sensitive=False)
        candidates = [candidate for char in "/." for candidate in regexp.generate(char, anchored=True)]
    except (*PARSE_ERRORS, RegexpTooComplex):
        return False
    for candidate in candidates:
        if not candidate.startswith("^"):
            return True
        body = candidate[1:]
        pinned_end = body.endswith("$")
        body = body[:-1] if pinned_end else body
        host = re.split(r"[/:]", body, maxsplit=1)[0]
        if not host or (host == body and not pinned_end):
            return True
    return False


class valid_referers(Plugin):
    """
    Insecure example:
        valid_referers none server_names *.webvisor.com;
    """

    summary = "valid_referers accepts a Referer an attacker can produce."
    severity = gixy.severity.HIGH
    description = '"none", and regexes or wildcards that also match other sites, let any site pass the referer check.'
    help_url = "https://gixy.io/plugins/valid_referers/"
    directives = ["valid_referers"]

    def audit(self, directive):
        if "none" in directive.args:
            reason = "`valid_referers` includes `none`, treating requests without a Referer as trusted."
            self.add_issue(directive=directive, reason=reason)
        elif "blocked" in directive.args:
            reason = (
                "`valid_referers` includes `blocked`, which accepts a Referer that does not start with "
                "`http://` or `https://`; browsers rarely send one."
            )
            self.add_issue(directive=directive, reason=reason, severity=gixy.severity.LOW)

        weak = [
            entry
            for entry in directive.args
            if (_is_open_regex(entry[1:]) if entry.startswith("~") else entry.split("/", 1)[0].endswith(".*"))
        ]
        if weak:
            reason = (
                "`valid_referers` entries `{entries}` also match a Referer from another site, "
                "one that carries the name in its path or appends a domain to it."
            ).format(entries="`, `".join(weak))
            self.add_issue(directive=directive, reason=reason, severity=gixy.severity.MEDIUM)
