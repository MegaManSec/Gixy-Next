import gixy
from gixy.core.utils import default_listens, parse_listen_key_and_default, resolve_inherited_single
from gixy.plugins.plugin import Plugin


class http2_misdirected_request(Plugin):
    """Flag TLS default servers with ssl_reject_handshake and HTTP/2 or HTTP/3 that do not always answer 421."""

    summary = "Missing HTTP/2 or HTTP/3 misdirected-request safeguard (return 421)."
    severity = gixy.severity.LOW
    description = (
        "With HTTP/2 or HTTP/3 enabled, connection reuse may cause requests to reach the default server of a "
        "TLS listen socket even when ssl_reject_handshake is set: a client that connected for another server "
        "on the socket may send a request for a name that no server handles. HTTP/1.1 requests with such a "
        "Host header reach it too. Answering every request with return 421 gives those misdirected requests "
        "a deterministic, spec-compliant rejection."
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

        servers = list(http_block.find_all_contexts_of_type("server"))
        defaults = default_listens(servers)
        sockets = self._sockets(servers)
        for server in servers:
            listens = [listen for listen in defaults.get(server, ()) if self._listen_is_ssl(listen)]
            if not listens:
                continue
            ssl_reject = resolve_inherited_single(server, "ssl_reject_handshake")
            if not ssl_reject or ssl_reject.args[0].lower() != "on":
                continue
            if self._is_on(server, "ssl_verify_client", default=False):
                continue
            exposed = [
                listen
                for listen in listens
                if self._socket_accepts_handshakes(server, sockets.get(self._socket_key(listen), ()))
                and self._serves_misdirected(server, listen, sockets.get(self._socket_key(listen), ()))
            ]
            if not exposed:
                continue
            if self._server_returns_421(server):
                continue
            protocols = sorted({"HTTP/3" if self._listen_is_quic(listen) else "HTTP/2" for listen in exposed})
            self.add_issue(
                directive=[ssl_reject] + exposed,
                reason=(
                    "The default server of a TLS listen socket with ssl_reject_handshake on and {protocols} enabled "
                    "should answer every request with return 421 (at server level, or from location / and every "
                    "other location) to reject misdirected requests.".format(protocols=" and ".join(protocols))
                ),
            )

    def _listen_is_ssl(self, listen):
        return any(arg.lower() in self.SSL_LISTEN_FLAGS for arg in listen.args)

    def _listen_is_quic(self, listen):
        return any(arg.lower() == "quic" for arg in listen.args[1:])

    def _socket_key(self, listen):
        if listen.args[0].lower().startswith("unix:"):
            return listen.args[0]
        return parse_listen_key_and_default(listen.args)[0]

    def _sockets(self, servers):
        sockets = {}
        for server in servers:
            for listen in server.find("listen"):
                key = self._socket_key(listen)
                if key is not None:
                    sockets.setdefault(key, []).append((server, listen))
        return sockets

    def _is_on(self, server, name, default):
        directive = resolve_inherited_single(server, name)
        if directive is None:
            return default
        return directive.args[0].lower() != "off"

    def _socket_accepts_handshakes(self, server, socket):
        return any(
            other is not server and not self._is_on(other, "ssl_reject_handshake", default=False)
            for other, _ in socket
        )

    def _serves_misdirected(self, server, listen, socket):
        if self._listen_is_quic(listen):
            return self._is_on(server, "http3", default=True)
        if any(arg.lower() == "http2" for _, other in socket for arg in other.args[1:]):
            return True
        return self._is_on(server, "http2", default=False)

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
