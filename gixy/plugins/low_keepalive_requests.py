import gixy
from gixy.plugins.plugin import Plugin


class low_keepalive_requests(Plugin):
    """
    Insecure example:
        keepalive_requests 100;
    """

    summary = "The keepalive_requests directive should be at least 1000."
    severity = gixy.severity.LOW
    description = "The keepalive_requests directive should be at least 1000. Any value lower than this may result in client disconnections."
    help_url = "https://gixy.io/plugins/low_keepalive_requests/"
    directives = ["keepalive_requests"]

    def audit(self, directive):
        if not directive.args:
            return
        try:
            value = int(directive.args[0])
        except (ValueError, TypeError, IndexError):
            return
        # upstream { keepalive_requests N; } is a different directive (since
        # 1.15.3): the max requests per cached upstream connection, where low
        # values are expected — not the client-facing limit this check targets.
        if any(parent.name == "upstream" for parent in directive.parents):
            return
        if value == 0:
            # nginx tests `connection->requests >= keepalive_requests` with no
            # zero guard, so 0 makes it always true: the connection is closed
            # after every request, disabling keep-alive entirely.
            self.add_issue(
                directive=directive,
                reason="`keepalive_requests 0` disables keep-alive: the connection is closed after every request.",
            )
        elif 0 < value < 1000:
            self.add_issue(
                directive=directive, reason=f"`keepalive_requests` is set to {value}."
            )
