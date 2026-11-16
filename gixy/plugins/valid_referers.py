import re

import gixy
from gixy.core.regexp import PARSE_ERRORS, RegexpTooComplex
from gixy.core.utils import HOST_PROBES, pins_registrable_domain
from gixy.plugins.plugin import Plugin


def _referer_host(text):
    return re.split(r"[/:]", text, maxsplit=1)[0]


def _is_open_regex(pattern):
    """True if `pattern`, matched against the Referer after its scheme, is not pinned to the start of
    that text, does not pin where the host name ends, or leaves part of the host's registrable domain
    to the client, so a Referer from another site can match it. `/` joins the probes because a
    wildcard that admits it ends the host name early."""
    try:
        return not pins_registrable_domain(pattern, HOST_PROBES + "/", _referer_host)
    except (*PARSE_ERRORS, RegexpTooComplex):
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
