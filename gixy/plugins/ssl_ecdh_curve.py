import gixy
from gixy.plugins.plugin import Plugin

PQ_GROUP_MARKERS = ("MLKEM", "KYBER")
ML_KEM_MARKER = "MLKEM"
TOLERANT_PREFIX = "?"
REMOVE_PREFIX = "-"
GROUP_PREFIXES = "?*-"
DEFAULT_KEYWORD = "DEFAULT"


def _group_name(group):
    return group.lstrip(GROUP_PREFIXES)


def _is_post_quantum(group):
    upper = _group_name(group).upper()
    return any(marker in upper for marker in PQ_GROUP_MARKERS)


def _is_ml_kem(group):
    return ML_KEM_MARKER in _group_name(group).upper()


def _is_removed(group):
    return REMOVE_PREFIX in group[: len(group) - len(_group_name(group))]


def _parse_tiers(curve_list):
    tiers = [[group for group in tier.split(":") if group] for tier in curve_list.split("/")]
    return [tier for tier in tiers if tier]


class ssl_ecdh_curve(Plugin):
    """Flag ssl_ecdh_curve lists that stop NGINX from starting or turn off post-quantum key exchange."""

    summary = "Post-quantum `ssl_ecdh_curve` group stops NGINX from starting on older OpenSSL."
    severity = gixy.severity.MEDIUM
    description = (
        "NGINX passes `ssl_ecdh_curve` straight to OpenSSL's `SSL_CTX_set1_curves_list()`, which "
        "rejects the *entire* list when a single group name is unknown to the linked library. NGINX "
        "logs that at emergency level and refuses to load the configuration, so a cold start fails and "
        "a reload silently keeps serving the old configuration. Post-quantum hybrids "
        "(`X25519MLKEM768`, `SecP256r1MLKEM768`) need OpenSSL 3.5+, and no OpenSSL release accepts the "
        "pre-standard `X25519Kyber768*` drafts; "
        "Debian 12, Ubuntu 24.04 and RHEL 9.0-9.6 ship OpenSSL 3.0/3.2. The `?` prefix makes OpenSSL skip "
        "groups it does not recognise, but `?` itself is only understood from OpenSSL 3.3 onwards — on "
        "OpenSSL 3.0/3.2 do not name post-quantum groups at all, and leave `ssl_ecdh_curve auto;`."
    )
    help_url = "https://gixy.io/plugins/ssl_ecdh_curve/"
    directives = ["ssl_ecdh_curve"]

    classical_summary = "`ssl_ecdh_curve` turns off post-quantum key exchange on OpenSSL 3.5+."
    classical_description = (
        "An explicit `ssl_ecdh_curve` list replaces OpenSSL's default group list instead of extending it. "
        "On OpenSSL 3.5+, whose default starts with a preference tier of post-quantum hybrids led by "
        "`X25519MLKEM768`, a list that offers no ML-KEM group, or ranks every one below a classical group, "
        "makes NGINX negotiate classical key exchange with clients that support the hybrid. `nginx -t` reports "
        "nothing, and recorded traffic stays exposed to a future quantum computer. On OpenSSL 3.0-3.4 "
        "nothing changes today, because those versions have no post-quantum groups. Removing the "
        "directive follows the library default, which is correct on every OpenSSL version."
    )

    shared_tier_summary = "`ssl_ecdh_curve` puts post-quantum and classical groups in one preference tier."
    shared_tier_description = (
        "OpenSSL 3.5 reads the group list as preference tiers: `:` joins groups in one tier and `/` starts "
        "the next. Inside a tier the server uses a key share the client already sent, so a client that "
        "offers the hybrid but sends its X25519 key share first negotiates classical X25519. "
        "`ssl_prefer_server_ciphers on` only helps when the client also sent a hybrid key share. Current "
        "browsers lead with the hybrid and are unaffected. Removing the directive fixes this on every "
        "OpenSSL version: the OpenSSL 3.5+ default starts with a tier of post-quantum hybrids. If the "
        "list must stay pinned on OpenSSL 3.5+, end "
        "the first tier after the post-quantum groups, as in `?X25519MLKEM768/X25519:prime256v1`. `/` is "
        "OpenSSL 3.5 syntax: OpenSSL 3.3 and 3.4 read `?X25519MLKEM768/X25519` as one unknown name and "
        "drop `X25519` with it."
    )

    def audit(self, directive):
        if not directive.args:
            return

        curve_list = directive.args[0]
        if curve_list == "auto":
            return

        tiers = _parse_tiers(curve_list)
        groups = [group for tier in tiers for group in tier]
        if not groups or any(_group_name(group).upper() == DEFAULT_KEYWORD for group in groups):
            return

        risky = [group for group in groups if _is_post_quantum(group) and not group.startswith(TOLERANT_PREFIX)]
        if risky:
            ml_kem = [group for group in risky if _is_ml_kem(group)]
            drafts = [group for group in risky if not _is_ml_kem(group)]
            reason = []
            if ml_kem:
                reason.append(
                    "Group(s) `{groups}` only exist in OpenSSL 3.5+. On an older OpenSSL the whole list is "
                    "rejected and NGINX fails to load this configuration.".format(groups="`, `".join(ml_kem))
                )
            if drafts:
                reason.append(
                    "Group(s) `{groups}` are pre-standard Kyber drafts that no OpenSSL release accepts, so "
                    "NGINX fails to load this configuration on every OpenSSL version.".format(
                        groups="`, `".join(drafts)
                    )
                )
            advice = "Remove the directive to use the OpenSSL default, which leads with `X25519MLKEM768` on 3.5+"
            if ml_kem:
                advice += ", or prefix `{groups}` with `?` if every target runs OpenSSL 3.3+".format(
                    groups="`, `".join(ml_kem)
                )
            reason.append(advice + ".")
            self.add_issue(directive=directive, reason=" ".join(reason))
            return

        offered = [[group for group in tier if not _is_removed(group)] for tier in tiers]
        offered = [tier for tier in offered if tier]
        if not any(_is_ml_kem(group) for tier in offered for group in tier):
            self.add_issue(
                directive=directive,
                summary=self.classical_summary,
                severity=gixy.severity.LOW,
                description=self.classical_description,
                reason=(
                    "`{curve_list}` offers no ML-KEM group, so NGINX linked against OpenSSL 3.5+ never "
                    "negotiates `X25519MLKEM768`, even with clients that offer it. Remove the directive to "
                    "use the OpenSSL default.".format(curve_list=curve_list)
                ),
            )
            return

        first_tier = offered[0]
        if not any(_is_ml_kem(group) for group in first_tier):
            self.add_issue(
                directive=directive,
                summary=self.classical_summary,
                severity=gixy.severity.LOW,
                description=self.classical_description,
                reason=(
                    "`{curve_list}` ranks every post-quantum group below `{classical}`, so NGINX linked "
                    "against OpenSSL 3.5+ negotiates a classical group with every client that supports one "
                    "from a higher tier. Remove the directive to use the OpenSSL default.".format(
                        curve_list=curve_list, classical=":".join(first_tier)
                    )
                ),
            )
            return

        classical = [group for group in first_tier if not _is_post_quantum(group)]
        if classical:
            self.add_issue(
                directive=directive,
                summary=self.shared_tier_summary,
                severity=gixy.severity.INFORMATION,
                description=self.shared_tier_description,
                reason=(
                    "The first preference tier of `{curve_list}` also holds `{classical}`, so a client that "
                    "leads with a classical key share negotiates it instead of the post-quantum hybrid on "
                    "OpenSSL 3.5+.".format(curve_list=curve_list, classical="`, `".join(classical))
                ),
            )
