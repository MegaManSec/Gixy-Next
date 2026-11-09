import gixy
from gixy.plugins.plugin import Plugin

PQ_GROUP_MARKERS = ("MLKEM", "KYBER")
ML_KEM_MARKER = "MLKEM"
HYBRID_GROUP = "X25519MLKEM768"
TOLERANT_PREFIX = "?"
KEY_SHARE_PREFIX = "*"
REMOVE_PREFIX = "-"
GROUP_PREFIXES = "?*-"
DEFAULT_KEYWORD = "DEFAULT"
GROUPS_CONF_COMMANDS = ("groups", "curves")


def _group_name(group):
    return group.lstrip(GROUP_PREFIXES)


def _group_prefix(group):
    return group[: len(group) - len(_group_name(group))]


def _is_post_quantum(group):
    upper = _group_name(group).upper()
    return any(marker in upper for marker in PQ_GROUP_MARKERS)


def _is_ml_kem(group):
    return ML_KEM_MARKER in _group_name(group).upper()


def _is_removal(group):
    return REMOVE_PREFIX in _group_prefix(group)


def _is_default_keyword(group):
    return _group_name(group).upper() == DEFAULT_KEYWORD


def _parse_tiers(curve_list):
    tiers = [[group.strip() for group in tier.split(":")] for tier in curve_list.split("/")]
    tiers = [[group for group in tier if group] for tier in tiers]
    return [tier for tier in tiers if tier]


def _offered_tiers(tiers):
    offered = []
    for tier in tiers:
        current = []
        offered.append(current)
        for group in tier:
            if not _is_removal(group):
                current.append(group)
                continue
            name = _group_name(group).upper()
            for kept in offered:
                kept[:] = [other for other in kept if _group_name(other).upper() != name]
    return [tier for tier in offered if tier]


def _removes_hybrid_after_default(groups):
    seen_default = False
    for group in groups:
        if _is_default_keyword(group):
            seen_default = True
        elif seen_default and _is_removal(group) and _group_name(group).upper() == HYBRID_GROUP.upper():
            return True
    return False


def _groups_overridden(directive):
    scope = directive.parent
    while scope:
        commands = [
            child
            for child in getattr(scope, "children", [])
            if (child.name or "").lower() == "ssl_conf_command" and child.args
        ]
        if commands:
            return any(command.args[0].lower() in GROUPS_CONF_COMMANDS for command in commands)
        scope = getattr(scope, "parent", None)
    return False


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
        "pre-standard `X25519Kyber768*` drafts; Debian 12, Ubuntu 22.04 and 24.04, RHEL 8, RHEL 9.0-9.6 "
        "and RHEL 10.0 ship OpenSSL 1.1.1 to 3.2. The `?` prefix makes OpenSSL skip "
        "groups it does not recognise, but `?` itself is only understood from OpenSSL 3.3 onwards — on "
        "older OpenSSL do not name post-quantum groups at all, and leave `ssl_ecdh_curve auto;`."
    )
    help_url = "https://gixy.io/plugins/ssl_ecdh_curve/"
    directives = ["ssl_ecdh_curve"]

    rejected_summary = "`ssl_ecdh_curve` value is rejected by OpenSSL, so NGINX does not start."
    rejected_description = (
        "NGINX passes every `ssl_ecdh_curve` value except the exact string `auto` to OpenSSL's "
        "`SSL_CTX_set1_curves_list()` and refuses to load the configuration when OpenSSL rejects it. "
        "A cold start fails and a reload silently keeps serving the old configuration, on every OpenSSL "
        "version."
    )

    pq_only_summary = "`ssl_ecdh_curve` offers only post-quantum groups."
    pq_only_description = (
        "A list of only `?`-prefixed post-quantum groups does not work on any OpenSSL version. OpenSSL "
        "before 3.3 rejects the `?` prefix, OpenSSL 3.3 and 3.4 skip every group they do not know and "
        "then reject the empty list, so NGINX fails to load the configuration. On OpenSSL 3.5+ the list "
        "loads, but clients that do not support a hybrid cannot complete a handshake. Remove the "
        "directive, or add classical groups after the post-quantum ones."
    )

    classical_summary = "`ssl_ecdh_curve` turns off post-quantum key exchange on OpenSSL 3.5+."
    classical_description = (
        "An explicit `ssl_ecdh_curve` list replaces OpenSSL's default group list instead of extending it. "
        "On OpenSSL 3.5+, whose default starts with a preference tier of post-quantum hybrids led by "
        "`X25519MLKEM768`, a list that offers no ML-KEM group, or ranks every one below a classical group, "
        "makes NGINX negotiate classical key exchange with clients that support the hybrid. `nginx -t` reports "
        "nothing, and recorded traffic stays exposed to a future quantum computer. On OpenSSL 1.1.1-3.4 a "
        "`:`-separated classical list changes nothing today, because those versions have no post-quantum "
        "groups; a list that uses `/`, `*`, `-` or `DEFAULT` does not load there at all. Removing the "
        "directive follows the library default, which loads on every OpenSSL version. Where a system crypto "
        "policy sets that default, as on RHEL 9.7 and Amazon Linux 2023, post-quantum key exchange also has "
        "to be enabled in the policy."
    )

    shared_tier_summary = "`ssl_ecdh_curve` puts post-quantum and classical groups in one preference tier."
    shared_tier_description = (
        "OpenSSL 3.5 reads the group list as preference tiers: `:` joins groups in one tier and `/` starts "
        "the next. Inside a tier the server uses a key share the client already sent, so a client that "
        "offers the hybrid but sends its X25519 key share first negotiates classical X25519. "
        "`ssl_prefer_server_ciphers on` only helps when the client also sent a hybrid key share. Current "
        "browsers lead with the hybrid and are unaffected. Removing the directive fixes this wherever the "
        "OpenSSL 3.5+ default applies, since it starts with a tier of post-quantum hybrids; a system "
        "crypto policy, as on RHEL 9.7 and Amazon Linux 2023, may leave post-quantum out of that default. "
        "If the list must stay pinned on OpenSSL 3.5+, end "
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
        if not groups:
            return

        if self._report_rejected(directive, curve_list, groups):
            return

        has_default = any(_is_default_keyword(group) for group in groups)
        risky = [
            group
            for group in groups
            if _is_post_quantum(group) and not _is_removal(group) and not group.startswith(TOLERANT_PREFIX)
        ]
        if risky and not has_default:
            self._report_startup_failure(directive, curve_list, groups, risky)
            return

        offered = _offered_tiers(tiers)
        offered_groups = [group for tier in offered for group in tier]
        if not has_default and offered_groups and all(_is_post_quantum(group) for group in offered_groups):
            self.add_issue(
                directive=directive,
                summary=self.pq_only_summary,
                description=self.pq_only_description,
                reason=(
                    "`{curve_list}` names no classical group. It does not load on OpenSSL before 3.5, and on "
                    "OpenSSL 3.5+ clients without a post-quantum hybrid cannot connect.".format(
                        curve_list=curve_list
                    )
                ),
            )
            return

        if _groups_overridden(directive):
            return

        if has_default:
            if _removes_hybrid_after_default(groups):
                self._report_classical(
                    directive,
                    "`{curve_list}` removes `{hybrid}` from the OpenSSL default, so NGINX negotiates classical "
                    "key exchange with clients that support only that hybrid, which includes current "
                    "browsers.".format(curve_list=curve_list, hybrid=HYBRID_GROUP),
                )
            return

        if not any(_is_ml_kem(group) for group in offered_groups):
            self._report_classical(
                directive,
                "`{curve_list}` offers no ML-KEM group, so NGINX linked against OpenSSL 3.5+ never "
                "negotiates `X25519MLKEM768`, even with clients that offer it. Remove the directive to "
                "use the OpenSSL default.".format(curve_list=curve_list),
            )
            return

        first_tier = offered[0]
        if not any(_is_ml_kem(group) for group in first_tier):
            self._report_classical(
                directive,
                "`{curve_list}` ranks every post-quantum group below `{classical}`, so NGINX linked "
                "against OpenSSL 3.5+ negotiates a classical group with every client that supports one "
                "from a higher tier. Remove the directive to use the OpenSSL default.".format(
                    curve_list=curve_list, classical=":".join(first_tier)
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

    def _report_rejected(self, directive, curve_list, groups):
        reason = None
        if curve_list.lower() == "auto":
            reason = (
                "NGINX only treats lowercase `auto` as the OpenSSL default and passes `{value}` to OpenSSL, "
                "which rejects it. Write `auto`, or remove the directive.".format(value=curve_list)
            )
        else:
            prefixed = [group for group in groups if _is_default_keyword(group) and _group_prefix(group)]
            if prefixed:
                reason = (
                    "OpenSSL accepts the `DEFAULT` keyword only without a prefix, so `{groups}` is a syntax "
                    "error and NGINX fails to load this configuration.".format(groups="`, `".join(prefixed))
                )
        if reason is None:
            return False
        self.add_issue(
            directive=directive,
            summary=self.rejected_summary,
            description=self.rejected_description,
            reason=reason,
        )
        return True

    def _report_startup_failure(self, directive, curve_list, groups, risky):
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
        newer_syntax = "/" in curve_list or any(
            _is_removal(group) or (KEY_SHARE_PREFIX in _group_prefix(group) and not _is_post_quantum(group))
            for group in groups
        )
        advice = "Remove the directive to use the OpenSSL default, which loads on every OpenSSL version"
        if ml_kem and not newer_syntax:
            advice += ", or make `?` the first character of `{groups}` if every target runs OpenSSL 3.3+".format(
                groups="`, `".join(ml_kem)
            )
        reason.append(advice + ".")
        if newer_syntax:
            reason.append(
                "The list also uses OpenSSL 3.5 syntax (`/`, `*` or `-`), so no prefix makes it load on "
                "older OpenSSL."
            )
        self.add_issue(directive=directive, reason=" ".join(reason))

    def _report_classical(self, directive, reason):
        self.add_issue(
            directive=directive,
            summary=self.classical_summary,
            severity=gixy.severity.LOW,
            description=self.classical_description,
            reason=reason,
        )
