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
    severity = gixy.severity.MEDIUM
    description = '"proxy_set_header" at a nested level replaces the whole set of headers inherited from parent levels.'
    help_url = "https://gixy.io/plugins/proxy_set_header_redefinition/"
    directives = ["server", "location"]

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
        directives = self.find_headers(directive)
        parent = directive.parent
        while parent is not None:
            directives.extend(
                d for d in self.find_headers(parent) if self.header_name(d) in dropped
            )
            parent = parent.parent

        reason = "Parent headers `{headers}` were dropped at this level.".format(
            headers="`, `".join(sorted(dropped))
        )
        self.add_issue(directive=directives, reason=reason)

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

    def get_headers(self, block):
        return {self.header_name(d) for d in self.find_headers(block) if d.args}
