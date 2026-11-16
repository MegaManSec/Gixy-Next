import gixy
from gixy.core.utils import (
    dynamic_certificates,
    enclosing_module,
    is_tls_listen,
    resolve_inherited_all,
    resolve_inherited_single,
    tls_sockets,
)
from gixy.plugins.plugin import Plugin

LETSENCRYPT_PREFIX = "/etc/letsencrypt/"
CERT_DIRECTIVES = ("ssl_certificate", "ssl_trusted_certificate")


def _is_letsencrypt(directive):
    return any(arg.startswith(LETSENCRYPT_PREFIX) for arg in directive.args)


class ssl_stapling_letsencrypt(Plugin):
    """Flag ssl_stapling enabled for a Let's Encrypt certificate, which no longer has an OCSP responder."""

    summary = "OCSP stapling is enabled for a Let's Encrypt certificate, which has no OCSP responder."
    severity = gixy.severity.LOW
    description = (
        "Let's Encrypt stopped putting OCSP URLs in its certificates on 2025-05-07 and shut its OCSP "
        "responders down on 2025-08-06, so `ssl_stapling` with one of its certificates staples nothing. "
        "Remove `ssl_stapling`, `ssl_stapling_verify` and any `ssl_trusted_certificate` kept only for "
        "stapling; keep stapling for CAs that still run OCSP responders."
    )
    help_url = "https://gixy.io/plugins/ssl_stapling_letsencrypt/"
    directives = ["server"]

    def __init__(self, config):
        super(ssl_stapling_letsencrypt, self).__init__(config)
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

        certificates = self._letsencrypt_certificates(server)
        if not certificates:
            return

        paths = []
        for certificate in certificates:
            paths.extend(
                arg for arg in certificate.args if arg.startswith(LETSENCRYPT_PREFIX)
            )

        self.add_issue(
            directive=[stapling] + certificates,
            reason=(
                "`{paths}` appears to be a Let's Encrypt certificate. Let's Encrypt retired its OCSP "
                "responders on 2025-08-06 and no longer publishes an OCSP URL, so `ssl_stapling on` "
                "here staples nothing.".format(paths="`, `".join(paths))
            ),
        )

    def _is_ssl_server(self, server):
        module = enclosing_module(server)
        if module is None:
            return any(is_tls_listen(listen) for listen in server.find("listen"))
        if id(module) not in self._tls_sockets:
            self._tls_sockets[id(module)] = tls_sockets(module.find_all_contexts_of_type("server"))
        return any(is_tls_listen(listen, self._tls_sockets[id(module)]) for listen in server.find("listen"))

    @staticmethod
    def _letsencrypt_certificates(server):
        certificates = resolve_inherited_all(server, "ssl_certificate")
        found = [directive for directive in certificates if _is_letsencrypt(directive)]
        if found or not certificates:
            found.extend(
                directive
                for directive in resolve_inherited_all(server, "ssl_trusted_certificate")
                if _is_letsencrypt(directive)
            )
        return found
