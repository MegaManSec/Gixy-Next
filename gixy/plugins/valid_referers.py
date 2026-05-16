import gixy
from gixy.plugins.plugin import Plugin


class valid_referers(Plugin):
    """
    Insecure example:
        valid_referers none server_names *.webvisor.com;
    """

    summary = "none used in valid_referers."
    severity = gixy.severity.HIGH
    description = (
        'Using "none" in valid_referers treats requests with no Referer as trusted, '
        "effectively disabling referer-based access control and clickjacking protection."
    )
    help_url = "https://gixy.io/plugins/valid_referers/"
    directives = ["valid_referers"]

    def audit(self, directive):
        if any(a.lower() == "none" for a in directive.args):
            reason = "`valid_referers` includes `none`, treating requests without a Referer as trusted."
            self.add_issue(directive=directive, reason=reason)
