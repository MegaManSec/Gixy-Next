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
                proxy_pass http://backend;
            }
        }
    """

    summary = 'Nested "proxy_set_header" drops parent headers.'
    severity = gixy.severity.MEDIUM
    description = (
        '"proxy_set_header" at a nested level stips off inherited headers from parent scopes.'
    )
    help_url = "https://gixy.io/plugins/proxy_set_header_redefinition/"
    directives = ["location", "if"]

    @staticmethod
    def _get_proxy_set_headers(block):
        """Return set of lowercased header names defined by proxy_set_header
        directly inside *block*."""
        headers = set()
        for d in block.find("proxy_set_header", flat=True):
            if d.args:
                headers.add(d.args[0].lower())
        return headers

    @staticmethod
    def _get_proxy_set_header_directives(block):
        """Return list of proxy_set_header directives inside *block*."""
        return block.find("proxy_set_header", flat=True)

    def _effective_parent_headers(self, block):
        """Walk up from *block* collecting effective proxy_set_header names.
        At each ancestor, if it defines any proxy_set_header, those win and
        we stop (nginx inheritance: nearest scope that declares any wins)."""
        node = getattr(block, "parent", None)
        while node is not None:
            headers = self._get_proxy_set_headers(node)
            if headers:
                return headers
            node = getattr(node, "parent", None)
        return set()

    def audit(self, directive):
        if not directive.is_block:
            return

        own = self._get_proxy_set_headers(directive)
        if not own:
            return  # no proxy_set_header defined here, inheriting normally

        parent_headers = self._effective_parent_headers(directive)
        if not parent_headers:
            return  # no parent headers to drop

        dropped = parent_headers - own
        if not dropped:
            return  # child explicitly re-declares all parent headers

        # Collect directives for report
        report_directives = list(self._get_proxy_set_header_directives(directive))
        parent = getattr(directive, "parent", None)
        if parent:
            report_directives.extend(self._get_proxy_set_header_directives(parent))

        reason = (
            "Headers declared in higher scopes `{headers}` are not effective here."
        ).format(headers="`, `".join(sorted(dropped)))

        self.add_issue(directive=report_directives, reason=reason)
