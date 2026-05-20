import gixy
from gixy.plugins.plugin import Plugin


class http2_misdirected_request(Plugin):
    """Flag TLS default_server blocks with ssl_reject_handshake and HTTP/2 that lack a location / returning 421."""

    summary = "Missing HTTP/2 misdirected-request safeguard (return 421)."
    severity = gixy.severity.LOW
    description = (
        "With HTTP/2 enabled, connection reuse may cause requests to reach a TLS default_server "
        "even when ssl_reject_handshake is set. A location / { return 421; } provides a "
        "deterministic, spec-compliant rejection of those misdirected requests."
    )
    help_url = "https://gixy.io/plugins/http2_misdirected_request/"
    directives = []
    supports_full_config = True

    def audit(self, directive):
        return

    def post_audit(self, root):
        http_block = root.some("http", flat=False)
        if not http_block:
            return

        http2_dir = http_block.some("http2")
        http2_global = bool(http2_dir and http2_dir.args and http2_dir.args[0].lower() == "on")

        for server in http_block.find_all_contexts_of_type("server"):
            ssl_reject = server.some("ssl_reject_handshake")
            if not ssl_reject or not ssl_reject.args or ssl_reject.args[0].lower() != "on":
                continue
            if not self._server_is_default(server):
                continue
            if not self._server_is_ssl(server):
                continue
            server_http2 = server.some("http2")
            if server_http2 and server_http2.args and server_http2.args[0].lower() == "off":
                continue
            if not http2_global and not self._server_has_http2(server):
                continue
            if self._has_location_returning_421(server):
                continue
            self.add_issue(
                directive=ssl_reject,
                reason=(
                    "default_server with ssl_reject_handshake on and HTTP/2 enabled "
                    "should define location / { return 421; } to reject misdirected HTTP/2 requests."
                ),
            )

    def _server_is_default(self, server):
        for listen in server.find("listen"):
            if any(t.lower() in ("default_server", "default") for t in listen.args):
                return True
        return False

    def _server_is_ssl(self, server):
        for listen in server.find("listen"):
            if any(t.lower() in ("ssl", "quic", "http3") for t in listen.args):
                return True
        return False

    def _server_has_http2(self, server):
        http2 = server.some("http2")
        if http2 and http2.args and http2.args[0].lower() == "on":
            return True
        for listen in server.find("listen"):
            if any(t.lower() == "http2" for t in listen.args):
                return True
        return False

    def _has_location_returning_421(self, server):
        for location in server.find("location", flat=True):
            if location.path != "/":
                continue
            if any(r.args and r.args[0] == "421" for r in location.find("return")):
                return True
        return False
