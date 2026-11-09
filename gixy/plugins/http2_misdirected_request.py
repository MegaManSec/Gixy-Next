import gixy
from gixy.core.utils import default_listens, resolve_inherited_single
from gixy.plugins.plugin import Plugin


class http2_misdirected_request(Plugin):
    """Flag TLS default servers with ssl_reject_handshake and HTTP/2 that do not answer every request with 421."""

    summary = "Missing HTTP/2 misdirected-request safeguard (return 421)."
    severity = gixy.severity.LOW
    description = (
        "With HTTP/2 enabled, connection reuse may cause requests to reach the default server of a TLS "
        "listen socket even when ssl_reject_handshake is set. Answering every request with return 421 "
        "gives those misdirected requests a deterministic, spec-compliant rejection."
    )
    help_url = "https://gixy.io/plugins/http2_misdirected_request/"
    directives = []
    supports_full_config = True

    SSL_LISTEN_FLAGS = ("ssl", "quic", "http3")

    def audit(self, directive):
        return

    def post_audit(self, root):
        http_block = root.some("http", flat=False)
        if not http_block:
            return

        http2_dir = http_block.some("http2")
        http2_global = bool(http2_dir and http2_dir.args and http2_dir.args[0].lower() == "on")

        servers = list(http_block.find_all_contexts_of_type("server"))
        defaults = default_listens(servers)
        for server in servers:
            listens = [listen for listen in defaults.get(server, ()) if self._listen_is_ssl(listen)]
            if not listens:
                continue
            ssl_reject = resolve_inherited_single(server, "ssl_reject_handshake")
            if not ssl_reject or ssl_reject.args[0].lower() != "on":
                continue
            server_http2 = server.some("http2")
            if server_http2 and server_http2.args and server_http2.args[0].lower() == "off":
                continue
            if not http2_global and not self._server_has_http2(server):
                continue
            if self._server_returns_421(server):
                continue
            self.add_issue(
                directive=[ssl_reject] + listens,
                reason=(
                    "The default server of a TLS listen socket with ssl_reject_handshake on and HTTP/2 enabled "
                    "should answer every request with return 421 (at server level, or from location / and every "
                    "other location) to reject misdirected HTTP/2 requests."
                ),
            )

    def _listen_is_ssl(self, listen):
        return any(arg.lower() in self.SSL_LISTEN_FLAGS for arg in listen.args)

    def _server_has_http2(self, server):
        http2 = server.some("http2")
        if http2 and http2.args and http2.args[0].lower() == "on":
            return True
        for listen in server.find("listen"):
            if any(t.lower() == "http2" for t in listen.args):
                return True
        return False

    def _has_return_421(self, block):
        return any(r.args and r.args[0] == "421" for r in block.find("return"))

    def _routable_locations(self, block):
        return [
            location
            for location in block.find("location")
            if not location.path.startswith("@") and not location.is_internal
        ]

    def _locations_to_check(self, block):
        """Routable locations a client can be served by: every prefix location, plus the regex
        ones only when some prefix location lacks `=`/`^~`, since NGINX skips them otherwise."""
        locations = self._routable_locations(block)
        prefix = [location for location in locations if not location.is_regex]
        if any(location.modifier is None for location in prefix):
            return locations
        return prefix

    def _location_returns_421(self, location):
        if not self._has_return_421(location):
            return False
        return all(self._location_returns_421(nested) for nested in self._locations_to_check(location))

    def _server_returns_421(self, server):
        if self._has_return_421(server):
            return True
        locations = self._locations_to_check(server)
        if not any(location.path == "/" and location.modifier in (None, "^~") for location in locations):
            return False
        return all(self._location_returns_421(location) for location in locations)
