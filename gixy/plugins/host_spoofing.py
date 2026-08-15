import gixy
from gixy.core.variable import EXTRACT_RE
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

        variables = [m.group(1).strip("{}") for m in EXTRACT_RE.finditer(value.lower())]
        arg = next((var for var in variables if var.startswith("arg_")), None)
        cookie = next((var for var in variables if var.startswith("cookie_")), None)
        if "http_host" in variables:
            reason = "Upstream Host is set from `$http_host`, which can be attacker-controlled. Prefer `$host`."
            self.add_issue(directive=directive, reason=reason)
        elif "http_x_forwarded_host" in variables:
            reason = "Upstream Host is set from `$http_x_forwarded_host` (X-Forwarded-Host request header), which is attacker-controlled. Prefer `$host`."
            self.add_issue(directive=directive, reason=reason)
        elif arg:
            reason = f"Upstream Host is set from query-string variable `${arg}`, which is attacker-controlled."
            self.add_issue(directive=directive, reason=reason)
        elif cookie:
            reason = f"Upstream Host is set from cookie variable `${cookie}`, which is attacker-controlled."
            self.add_issue(directive=directive, reason=reason)
