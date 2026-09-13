import gixy
from gixy.plugins.plugin import Plugin

PQ_GROUP_MARKERS = ("MLKEM", "KYBER")
TOLERANT_PREFIX = "?"


def _is_post_quantum(group):
    if group.startswith(TOLERANT_PREFIX):
        return False
    upper = group.upper()
    return any(marker in upper for marker in PQ_GROUP_MARKERS)


class ssl_ecdh_curve(Plugin):
    """Flag post-quantum ssl_ecdh_curve groups that stop NGINX from starting on older OpenSSL."""

    summary = "Post-quantum `ssl_ecdh_curve` group stops NGINX from starting on older OpenSSL."
    severity = gixy.severity.MEDIUM
    description = (
        "NGINX passes `ssl_ecdh_curve` straight to OpenSSL's `SSL_CTX_set1_curves_list()`, which "
        "rejects the *entire* list when a single group name is unknown to the linked library. NGINX "
        "logs that at emergency level and refuses to load the configuration, so a cold start fails and "
        "a reload silently keeps serving the old configuration. Post-quantum hybrids "
        "(`X25519MLKEM768`, `SecP256r1MLKEM768`, the `X25519Kyber768*` drafts) need OpenSSL 3.5+; "
        "Debian 12, Ubuntu 24.04 and RHEL 9 ship OpenSSL 3.0/3.2. The `?` prefix makes OpenSSL skip "
        "groups it does not recognise, but `?` itself is only understood from OpenSSL 3.3 onwards — on "
        "OpenSSL 3.0/3.2 do not name post-quantum groups at all, and leave `ssl_ecdh_curve auto;`."
    )
    help_url = "https://gixy.io/plugins/ssl_ecdh_curve/"
    directives = ["ssl_ecdh_curve"]

    def audit(self, directive):
        if not directive.args:
            return

        groups = [group for group in directive.args[0].split(":") if group]
        risky = [group for group in groups if _is_post_quantum(group)]
        if not risky:
            return

        self.add_issue(
            directive=directive,
            reason=(
                "Group(s) `{groups}` only exist in OpenSSL 3.5+. On an older OpenSSL the whole list is "
                "rejected and NGINX fails to load this configuration. Prefix them with `?` if every "
                "target runs OpenSSL 3.3+, otherwise drop them and use `auto` or classical curves.".format(
                    groups="`, `".join(risky)
                )
            ),
        )
