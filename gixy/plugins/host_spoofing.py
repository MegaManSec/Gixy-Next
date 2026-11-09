import gixy
from gixy.core.utils import resolve_variable_chain
from gixy.core.variable import EXTRACT_RE
from gixy.directives.directive import SetDirective
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
        name = directive.arg(0)
        value = directive.arg(1)
        if name.lower() != "host":
            # Not a "Host" header
            return

        source = self._untrusted_source(value)
        if source:
            self.add_issue(directive=directive, reason="Upstream Host is set from " + source)
            return

        def assignments(var):
            for sd in directive.find_declarative_directives_in_scope("set"):
                if isinstance(sd, SetDirective) and sd.variable == var:
                    yield sd, sd.value

        for var in self._variables(value):
            for hops, assigned in resolve_variable_chain(var, assignments):
                source = self._untrusted_source(assigned)
                if not source:
                    continue
                reason = f"Upstream Host is set from `${var}`, which is assigned from " + source
                self.add_issue(directive=[directive] + list(hops), reason=reason)
                return

    @staticmethod
    def _variables(value):
        return [m.group(1).strip("{}") for m in EXTRACT_RE.finditer(value.lower())]

    @classmethod
    def _untrusted_source(cls, value):
        variables = cls._variables(value)
        arg = next((var for var in variables if var.startswith("arg_")), None)
        cookie = next((var for var in variables if var.startswith("cookie_")), None)
        if "http_host" in variables:
            return "`$http_host`, which can be attacker-controlled. Prefer `$host`."
        if "http_x_forwarded_host" in variables:
            return (
                "`$http_x_forwarded_host` (X-Forwarded-Host request header), "
                "which is attacker-controlled. Prefer `$host`."
            )
        if arg:
            return f"query-string variable `${arg}`, which is attacker-controlled."
        if cookie:
            return f"cookie variable `${cookie}`, which is attacker-controlled."
        return None
