import re

import gixy
from gixy.core.utils import dynamic_certificates, enclosing_module, is_tls_listen, resolve_inherited_single, tls_sockets
from gixy.directives.directive import is_ipv4, is_ipv6
from gixy.plugins.plugin import Plugin

_SCHEME_RE = re.compile(r'^https?://', re.IGNORECASE)


def _responder_host(url):
    """Return the host portion of an ssl_stapling_responder URL, or None."""
    url = _SCHEME_RE.sub('', url)
    # Strip path/query/fragment
    url = url.split('/')[0]
    # Strip port from non-bracketed hosts
    if url.startswith('['):
        # IPv6 bracketed: [addr] or [addr]:port
        bracket_end = url.find(']')
        if bracket_end == -1:
            return None
        return url[:bracket_end + 1]
    url = url.rsplit(':', 1)[0]
    return url or None


class ssl_stapling_without_resolver(Plugin):
    """Flag SSL servers where ssl_stapling is on but no resolver is reachable in scope."""

    summary = "ssl_stapling enabled without a resolver — the OCSP responder is only resolved at startup."
    severity = gixy.severity.LOW
    description = (
        "Without a `resolver` in scope, nginx resolves the OCSP responder only at startup; if its "
        "addresses change, stapling stops once the last response expires. Add `resolver` to the "
        "server or http block, or pre-load the response with `ssl_stapling_file`."
    )
    help_url = "https://gixy.io/plugins/ssl_stapling_without_resolver/"
    directives = ["server"]

    def __init__(self, config):
        super(ssl_stapling_without_resolver, self).__init__(config)
        self._tls_sockets = {}

    def audit(self, server):
        if not server.is_block:
            return

        if not self._is_ssl_server(server):
            return

        stapling = resolve_inherited_single(server, "ssl_stapling")
        if not stapling or stapling.arg(0).lower() != "on":
            return
        if resolve_inherited_single(server, "ssl_stapling_file") or dynamic_certificates(server):
            return

        responder = resolve_inherited_single(server, "ssl_stapling_responder")
        if responder:
            host = _responder_host(responder.arg(0))
            if host and (is_ipv4(host) or is_ipv6(host) or host.lower() == "localhost"):
                return

        if resolve_inherited_single(server, "resolver"):
            return

        self.add_issue(
            directive=stapling,
            reason=(
                "ssl_stapling is enabled but no `resolver` is reachable in this server's scope — "
                "the OCSP responder is resolved only at startup and never refreshed."
            ),
        )

    def _is_ssl_server(self, server):
        module = enclosing_module(server)
        if module is None:
            return any(is_tls_listen(listen) for listen in server.find("listen"))
        if id(module) not in self._tls_sockets:
            self._tls_sockets[id(module)] = tls_sockets(module.find_all_contexts_of_type("server"))
        return any(is_tls_listen(listen, self._tls_sockets[id(module)]) for listen in server.find("listen"))
