import gixy
from gixy.plugins.plugin import Plugin


class proxy_buffering_off(Plugin):
    """
    Insecure examples:
        proxy_buffering off;
        fastcgi_request_buffering off;
    """

    summary = "Do not disable response or request buffering for upstreams."
    severity = gixy.severity.MEDIUM
    description = (
        "Disabling response or request buffering can increase slow-client DoS risk by tying up "
        "upstream connections and the backend workers serving them."
    )
    help_url = "https://gixy.io/plugins/proxy_buffering_off/"
    directives = [
        "proxy_buffering",
        "fastcgi_buffering",
        "uwsgi_buffering",
        "scgi_buffering",
        "proxy_request_buffering",
        "fastcgi_request_buffering",
        "uwsgi_request_buffering",
        "scgi_request_buffering",
    ]

    def audit(self, directive):
        if directive.args and directive.args[0].lower() == "off":
            self.add_issue(
                directive=directive,
                severity=gixy.severity.LOW if directive.name.endswith("_request_buffering") else self.severity,
                reason="`{name}` is set to `off`.".format(name=directive.name),
            )
