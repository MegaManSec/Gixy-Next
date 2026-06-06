import gixy
from gixy.plugins.plugin import Plugin


class add_header_content_type(Plugin):
    """
    Bad example: add_header Content-Type text/plain;
    Good example: default_type text/plain;
    """

    summary = "Setting Content-Type via add_header."
    severity = gixy.severity.LOW
    description = "Do not set Content-Type using add_header; use default_type instead."
    help_url = "https://gixy.io/plugins/add_header_content_type/"
    directives = ["add_header", "more_set_headers"]

    def audit(self, directive):
        ct_value = next(
            (v for h, v in directive.headers.items() if h.lower() == "content-type"),
            None,
        )
        if ct_value is None:
            return

        # Check if *_hide_header Content-Type is present in the same scope
        # This is a valid pattern to override backend Content-Type
        if self._has_hide_header_content_type(directive):
            return

        reason = "Use `default_type {default_type};` instead of `add_header`/`more_set_headers` to set Content-Type.".format(
            default_type=ct_value
        )
        self.add_issue(directive=directive, reason=reason)

    def _has_hide_header_content_type(self, directive):
        """Check if *_hide_header Content-Type exists in the same scope or parent scopes"""
        # List of nginx directives that can hide headers from backend
        hide_header_directives = [
            "proxy_hide_header",
            "fastcgi_hide_header",
            "uwsgi_hide_header",
            "scgi_hide_header",
            "grpc_hide_header",
        ]

        # Check in the same block (parent)
        if directive.parent:
            for hide_directive in hide_header_directives:
                hide_headers = directive.parent.find(hide_directive)
                for hh in hide_headers:
                    # hide_header has one argument: the header name
                    if hh.args and hh.args[0].lower() == "content-type":
                        return True

        # Also check in parent scopes (server, http, etc.) because *_hide_header is inherited
        for parent in directive.parents:
            for hide_directive in hide_header_directives:
                hide_headers = parent.find(hide_directive)
                for hh in hide_headers:
                    if hh.args and hh.args[0].lower() == "content-type":
                        return True

        return False
