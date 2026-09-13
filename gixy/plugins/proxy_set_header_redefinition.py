import gixy
from gixy.plugins.plugin import Plugin


class proxy_set_header_redefinition(Plugin):
    """
    Insecure example:
        server {
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Host $host;

            location / {
                proxy_set_header X-Real-IP $remote_addr;
                proxy_pass http://backend;
            }
        }

    Secure example:
        server {
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Host $host;

            location / {
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_pass http://backend;
            }
        }
    """

    summary = 'Nested "proxy_set_header" drops parent headers.'
    severity = gixy.severity.LOW
    description = '"proxy_set_header" at a nested level replaces the whole set of headers inherited from parent levels.'
    help_url = "https://gixy.io/plugins/proxy_set_header_redefinition/"
    directives = ["server", "location"]

    def __init__(self, config):
        super(proxy_set_header_redefinition, self).__init__(config)
        # Request headers that tell the upstream who the client really is, or
        # that overwrite a value the client must not be able to choose
        self.secure_headers = [
            "authorization",
            "early-data",
            "forwarded",
            "host",
            "proxy-authorization",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
        ]

    def audit(self, directive):
        if not directive.is_block:
            return

        own = self.get_headers(directive)
        if not own:
            return

        dropped = self.inherited_headers(directive) - own
        if not dropped:
            return

        self._report_issue(directive, dropped)

    def _report_issue(self, directive, dropped):
        dropped_directives = []
        parent = directive.parent
        while parent is not None:
            dropped_directives.extend(
                d for d in self.find_headers(parent) if self.header_name(d) in dropped
            )
            parent = parent.parent

        directives = self.find_headers(directive)
        directives.extend(dropped_directives)

        is_secure_header_dropped = any(
            h in self.secure_headers for h in dropped
        ) or any(self.is_blanked(d) for d in dropped_directives)
        issue_severity = (
            gixy.severity.MEDIUM if is_secure_header_dropped else self.severity
        )

        reason = "Parent headers `{headers}` were dropped at this level.".format(
            headers="`, `".join(sorted(dropped))
        )
        self.add_issue(directive=directives, reason=reason, severity=issue_severity)

    def inherited_headers(self, directive):
        """
        Headers in effect at the parent level: the nearest ancestor that declares
        any "proxy_set_header" replaces everything declared above it.
        """
        parent = directive.parent
        while parent is not None:
            headers = self.get_headers(parent)
            if headers:
                return headers
            parent = parent.parent
        return set()

    @staticmethod
    def find_headers(block):
        return block.find("proxy_set_header", flat=True)

    @staticmethod
    def header_name(directive):
        return directive.args[0].lower() if directive.args else None

    @staticmethod
    def is_blanked(directive):
        return len(directive.args) > 1 and not directive.args[1]

    def get_headers(self, block):
        return {self.header_name(d) for d in self.find_headers(block) if d.args}
