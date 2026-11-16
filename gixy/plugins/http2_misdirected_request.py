import gixy
from gixy.core.utils import (
    default_listens,
    error_page_for,
    is_tls_listen,
    listen_sockets,
    parse_listen_key_and_default,
    resolve_inherited_single,
    tls_sockets,
)
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

    def audit(self, directive):
        return

    def post_audit(self, root):
        http_block = root.some("http", flat=False)
        if not http_block:
            return

        servers = list(http_block.find_all_contexts_of_type("server"))
        defaults = default_listens(servers)
        sockets = listen_sockets(servers)
        tls = tls_sockets(servers)
        for server in servers:
            ssl_reject = resolve_inherited_single(server, "ssl_reject_handshake")
            if not ssl_reject or ssl_reject.args[0].lower() != "on":
                continue
            if self._is_on(server, "ssl_verify_client", default=False):
                continue
            exposed = [
                listen
                for listen in defaults.get(server, ())
                if is_tls_listen(listen, tls) and self._exposed(server, listen, sockets)
            ]
            if not exposed or self._server_returns_421(server):
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

    def _listen_is_quic(self, listen):
        return any(arg.lower() == "quic" for arg in listen.args[1:])

    def _is_on(self, server, name, default):
        directive = resolve_inherited_single(server, name)
        if directive is None:
            return default
        return directive.args[0].lower() != "off"

    def _exposed(self, server, listen, sockets):
        socket = sockets[parse_listen_key_and_default(listen.args)[0]]
        if not any(
            other is not server and not self._is_on(other, "ssl_reject_handshake", default=False)
            for other, _, _ in socket
        ):
            return False
        if self._listen_is_quic(listen):
            return self._is_on(server, "http3", default=True)
        return self._is_on(server, "http2", default=False) or any(
            arg.lower() == "http2" for _, other, _ in socket if other for arg in other.args[1:]
        )

    def _rewrites_421(self, block):
        page = error_page_for(block, "421")
        return page is not None and (
            not page.args[-1].startswith(("/", "@")) or (page.args[-2].startswith("=") and page.args[-2] != "=421")
        )

    def _has_return_421(self, block):
        return any(
            r.args and r.args[0] == "421" and (any(r.args[1:]) or not self._rewrites_421(block))
            for r in block.find("return")
        )

    def _routable_locations(self, block):
        return [
            location
            for location in block.find("location")
            if not location.path.startswith("@") and not location.is_internal
        ]

    def _location_returns_421(self, location):
        return self._has_return_421(location) and all(
            self._location_returns_421(nested) for nested in self._routable_locations(location)
        )

    def _server_returns_421(self, server):
        if self._has_return_421(server):
            return True
        locations = self._routable_locations(server)
        prefix = [location for location in locations if not location.is_regex]
        if not any(location.path == "/" and location.modifier in (None, "^~") for location in prefix):
            return False
        if all(location.modifier for location in prefix):
            locations = prefix
        return all(self._location_returns_421(location) for location in locations)
