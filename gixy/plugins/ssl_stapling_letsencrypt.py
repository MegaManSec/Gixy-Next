import gixy
from gixy.plugins.plugin import Plugin

LETSENCRYPT_PREFIX = "/etc/letsencrypt/"
CERT_DIRECTIVES = ("ssl_certificate", "ssl_trusted_certificate")


class ssl_stapling_letsencrypt(Plugin):
    """Flag ssl_stapling enabled for a Let's Encrypt certificate, which no longer has an OCSP responder."""

    summary = "OCSP stapling is enabled for a Let's Encrypt certificate, which has no OCSP responder."
    severity = gixy.severity.LOW
    description = (
        "Let's Encrypt stopped publishing OCSP URLs in its certificates in early 2025 and shut its "
        "OCSP responders down on 2025-08-06. With no responder URL in the certificate NGINX has "
        "nothing to fetch, logs `\"ssl_stapling\" ignored, no OCSP responder URL in the certificate` "
        "at startup, and staples nothing — the directives are dead configuration. Let's Encrypt now "
        "relies on short certificate lifetimes and CRLs for revocation. Remove `ssl_stapling`, "
        "`ssl_stapling_verify`, and any `ssl_trusted_certificate` that exists only to serve stapling. "
        "Keep stapling for CAs that still run OCSP responders."
    )
    help_url = "https://gixy.io/plugins/ssl_stapling_letsencrypt/"
    directives = ["server"]

    def audit(self, server):
        if not server.is_block:
            return

        if not self._is_ssl_server(server):
            return

        stapling = self._effective(server, "ssl_stapling")
        if not stapling or not stapling.args or stapling.args[0].lower() != "on":
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
                "here is a silent no-op.".format(paths="`, `".join(paths))
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

    def _letsencrypt_certificates(self, server):
        found = []
        for scope in [server] + list(server.parents):
            for name in CERT_DIRECTIVES:
                for directive in scope.find(name):
                    if any(
                        arg.startswith(LETSENCRYPT_PREFIX) for arg in directive.args
                    ):
                        found.append(directive)
        return found
