import gixy
from gixy.plugins.plugin import Plugin


class host_spoofing(Plugin):
    """
    Insecure example:
        proxy_set_header Host $http_host
    """

    summary = "The proxied Host header may be spoofed."
    severity = gixy.severity.HIGH
    description = "In most cases, the $host variable is more appropriate; prefer it over $http_host."
    help_url = "https://gixy.io/plugins/host_spoofing/"
    directives = ["proxy_set_header"]

    def audit(self, directive):
        name, value = directive.args
        if name.lower() != "host":
            # Not a "Host" header
            return

        if value.lower() == "$http_host":
            reason = "Upstream Host is set from `$http_host`, which can be attacker-controlled. Prefer `$host`."
            self.add_issue(directive=directive, reason=reason)
        elif value.lower().startswith("$arg_"):
            reason = f"Upstream Host is set from query-string variable `{value}`, which is attacker-controlled."
            self.add_issue(directive=directive, reason=reason)
