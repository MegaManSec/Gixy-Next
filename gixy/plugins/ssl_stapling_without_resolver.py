import gixy
from gixy.plugins.plugin import Plugin


class ssl_stapling_without_resolver(Plugin):
    """Flag SSL servers where ssl_stapling is on but no resolver is reachable in scope."""

    summary = "ssl_stapling enabled without a resolver — OCSP stapling silently fails."
    severity = gixy.severity.MEDIUM
    description = (
        "`ssl_stapling on` requires a `resolver` directive reachable in the same or a parent "
        "scope. Without it nginx cannot fetch the OCSP response and stapling silently fails — "
        "clients fall back to their own OCSP queries, adding handshake latency. "
        "Add `resolver` to the server or http block, or pre-load the stapled response with "
        "`ssl_stapling_file`."
    )
    help_url = "https://gixy.io/plugins/ssl_stapling_without_resolver/"
    directives = ["server"]

    def audit(self, server):
        if not server.is_block:
            return

        if not self._is_ssl_server(server):
            return

        stapling = self._effective(server, "ssl_stapling")
        if not stapling or not stapling.args or stapling.args[0].lower() != "on":
            return

        # ssl_stapling_file pre-loads the OCSP response; no resolver needed.
        if self._in_scope(server, "ssl_stapling_file"):
            return

        if self._in_scope(server, "resolver"):
            return

        self.add_issue(
            directive=stapling,
            reason=(
                "ssl_stapling is enabled but no `resolver` is reachable in this server's scope — "
                "OCSP stapling will silently fail at runtime."
            ),
        )

    def _is_ssl_server(self, server):
        for listen in server.find("listen"):
            if any(arg.lower() in ("ssl", "quic", "http3") for arg in listen.args):
                return True
        return False

    def _effective(self, server, name):
        own = server.some(name)
        if own:
            return own
        for parent in server.parents:
            inherited = parent.some(name, flat=False)
            if inherited:
                return inherited
        return None

    def _in_scope(self, server, name):
        if server.some(name):
            return True
        for parent in server.parents:
            if parent.some(name, flat=False):
                return True
        return False
