import gixy
from gixy.plugins.plugin import Plugin


class resolver_external(Plugin):
    """
    Syntax for the directive: resolver 127.0.0.1 [::1]:5353 valid=30s;
    """

    summary = "Using external DNS nameservers for resolver."
    severity = gixy.severity.MEDIUM
    description = (
        "Using external nameservers allows an attacker to send spoofed DNS replies to poison the resolver cache, "
        "causing NGINX to proxy requests to an arbitrary upstream server."
    )
    help_url = "https://gixy.io/plugins/resolver_external/"
    directives = ["resolver"]

    def audit(self, directive):
        bad_nameservers = directive.get_external_nameservers()
        if bad_nameservers:
            self.add_issue(
                directive=directive,
                reason="Resolver uses external DNS servers: `{dns_servers}`.".format(
                    dns_servers=", ".join(bad_nameservers)
                ),
            )
