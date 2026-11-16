import re

import gixy
from gixy.plugins.plugin import Plugin


class low_keepalive_requests(Plugin):
    """
    Insecure example:
        keepalive_requests 100;
    """

    summary = "keepalive_requests is below 1000, or keep-alive is disabled."
    severity = gixy.severity.LOW
    description = (
        "The keepalive_requests directive should be at least 1000, and keepalive_timeout "
        "should not be 0. Lower values may result in client disconnections."
    )
    help_url = "https://gixy.io/plugins/low_keepalive_requests/"
    directives = ["keepalive_requests", "keepalive_timeout", "keepalive_time"]

    ZERO_TIME = re.compile(r"(?:0+(?:ms|[yMwdhms])?)+")

    def audit(self, directive):
        if not directive.args:
            return
        # upstream { keepalive_requests N; keepalive_timeout T; } are different
        # directives (since 1.15.3) for cached upstream connections, where low
        # values are expected — not the client-facing limits this check targets.
        if any(parent.name == "upstream" for parent in directive.parents):
            return
        if directive.name != "keepalive_requests":
            if self.ZERO_TIME.fullmatch(directive.args[0]):
                if directive.name == "keepalive_timeout":
                    self._report_disabled(directive, "connections are closed before serving a request")
                else:
                    self._report_disabled(directive, "connections are closed after their first request")
            return
        try:
            value = int(directive.args[0])
        except (ValueError, TypeError, IndexError):
            return
        if value == 0:
            # nginx tests `connection->requests >= keepalive_requests` with no
            # zero guard, so 0 makes it always true: the connection is closed
            # after every request, disabling keep-alive entirely.
            self._report_disabled(directive, "every request is refused")
        elif 0 < value < 1000:
            self.add_issue(
                directive=directive, reason=f"`keepalive_requests` is set to {value}."
            )

    def _report_disabled(self, directive, http3):
        reason = (
            f"`{directive.name} {directive.args[0]}` disables keep-alive: "
            "the connection is closed after every request"
        )
        if any(parent.name == "location" for parent in directive.parents):
            reason += " (HTTP/1.x only: HTTP/2 and HTTP/3 use the server-level value)."
        else:
            reason += f", and on HTTP/3, {http3}."
        self.add_issue(directive=directive, reason=reason)
