import ipaddress

import gixy
from gixy.core.utils import AUTH_DIRECTIVES, resolve_inherited_single
from gixy.plugins.plugin import Plugin

ALL_RULE = "all"
UNIX_RULE = "unix:"
ALLOW_ALL_RULES = frozenset((ALL_RULE, "0.0.0.0/0", "::/0"))
INET, INET6, UNIX = "inet", "inet6", "unix"
UNIVERSE = {
    INET: ipaddress.ip_network("0.0.0.0/0"),
    INET6: ipaddress.ip_network("::/0"),
    UNIX: ipaddress.ip_network("0.0.0.0/32"),
}
V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def _exclude(region, networks):
    """`region` (disjoint networks) minus `networks`; CIDR blocks either nest or are disjoint."""
    for network in networks:
        rest = []
        for piece in region:
            if network.supernet_of(piece):
                continue
            if piece.supernet_of(network):
                rest.extend(piece.address_exclude(network))
            else:
                rest.append(piece)
        region = rest
    return region


def _overlaps(region, networks):
    return any(piece.overlaps(network) for piece in region for network in networks)


class _Rule(object):
    """One `allow`/`deny` directive as ngx_http_access_module stores it: in the IPv4, IPv6 and
    unix rule lists it belongs to (`all` joins all three), with the network it matches."""

    def __init__(self, directive):
        self.directive = directive
        self.allow = directive.name == "allow"
        self.families = ()
        self.network = None
        value = directive.args[0]
        if value == ALL_RULE:
            self.families = (INET, INET6, UNIX)
        elif value == UNIX_RULE:
            self.families = (UNIX,)
        else:
            try:
                self.network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return
            self.families = (INET if self.network.version == 4 else INET6,)

    def coverage(self, family):
        if self.network is not None:
            return [self.network]
        return [UNIVERSE[family]]

    def __str__(self):
        return str(self.directive)


class allow_without_deny(Plugin):
    """
    Simulate ngx_http_access_handler() over the `allow`/`deny` rules of a context: warn when
    the `allow` directives are not paired with a `deny` that would otherwise have caught some of
    their addresses, and when a rule is shadowed by earlier rules and never applies.
    """

    summary = "Allow directives without a deny restriction."
    severity = gixy.severity.HIGH
    description = (
        "Allow directives should typically be paired with a restrictive deny rule "
        "(for example, deny all;) in the same context."
    )
    help_url = "https://gixy.io/plugins/allow_without_deny/"
    directives = ["allow"]

    shadowed_deny_summary = "A `deny` rule is shadowed by an earlier `allow` and never applies."
    shadowed_allow_summary = "An `allow` rule is shadowed by an earlier `deny` and never applies."
    shadowed_description = (
        "NGINX checks `allow` and `deny` rules in order and stops at the first match. A rule whose "
        "addresses are all matched by earlier rules of the opposite kind never applies, so the "
        "configuration does not do what it says: those clients stay allowed, or stay denied. "
        "IPv4-mapped IPv6 clients are checked against the IPv4 rules whenever any exist."
    )

    def __init__(self, config):
        super(allow_without_deny, self).__init__(config)
        self._reported_parents = set()

    def _is_satisfy_any_with_auth(self, scope):
        """True for the intended 'IP allowlist OR authentication' pattern.

        Under `satisfy any`, clients outside the allow list get NGX_DECLINED
        from the access module and fall through to the auth modules, so a
        missing `deny all` changes nothing: they still must authenticate.
        Without an auth module the allow list is decorative and the warning
        stands.
        """
        satisfy = resolve_inherited_single(scope, "satisfy")
        if satisfy is None or satisfy.args[0].lower() != "any":
            return False
        for name in AUTH_DIRECTIVES:
            auth = resolve_inherited_single(scope, name)
            if auth is not None and auth.args[0].lower() != "off":
                return True
        return False

    @staticmethod
    def _simulate(rules):
        """Walk each family's rule list the way nginx does.

        Returns (shadowed, effective): `shadowed` maps a rule that can never match in any of
        its families to (opposite-kind rules that take its clients, mapped) where `mapped` says
        the IPv4 list took them; `effective` holds the allows that let through some client a
        later deny would otherwise have caught.
        """
        has_inet = any(INET in rule.families for rule in rules)
        dead_in = {rule: {} for rule in rules}
        effective = set()
        for family in (INET, INET6, UNIX):
            listed = [rule for rule in rules if family in rule.families]
            seen = [V4_MAPPED] if family == INET6 and has_inet else []
            for index, rule in enumerate(listed):
                coverage = rule.coverage(family)
                remaining = _exclude(coverage, seen)
                if not remaining:
                    shadows = [
                        earlier
                        for earlier in listed[:index]
                        if earlier.allow != rule.allow and _overlaps(earlier.coverage(family), coverage)
                    ]
                    mapped = not shadows and family == INET6 and has_inet and _overlaps(coverage, [V4_MAPPED])
                    if mapped:
                        shadows += [
                            other
                            for other in rules
                            if INET in other.families and other.allow != rule.allow
                        ]
                    dead_in[rule][family] = (shadows, mapped)
                elif rule.allow:
                    later = [
                        network
                        for other in listed[index + 1:]
                        if not other.allow
                        for network in other.coverage(family)
                    ]
                    if _overlaps(remaining, later):
                        effective.add(rule)
                seen = seen + remaining
        shadowed = {}
        for rule in rules:
            if len(dead_in[rule]) != len(rule.families):
                continue
            shadows = []
            mapped = False
            for family_shadows, family_mapped in dead_in[rule].values():
                shadows += [shadow for shadow in family_shadows if shadow not in shadows]
                mapped = mapped or family_mapped
            if shadows:
                shadowed[rule] = (shadows, mapped)
        return shadowed, effective

    def audit(self, directive):
        parent = directive.parent
        if not parent or not directive.args:
            return
        key = id(parent)
        if key in self._reported_parents:
            return
        self._reported_parents.add(key)

        rules = [_Rule(child) for child in parent.children if child.name in ("allow", "deny") and child.args]
        rules = [rule for rule in rules if rule.families]
        shadowed, effective = self._simulate(rules)

        for rule, (shadows, mapped) in shadowed.items():
            self._report_shadowed(rule, shadows, mapped)

        allows = [
            rule
            for rule in rules
            if rule.allow and rule.directive.args[0] not in ALLOW_ALL_RULES and rule not in shadowed
        ]
        if not allows or self._is_satisfy_any_with_auth(parent):
            return
        if any(rule in effective for rule in allows):
            return

        denies = [rule.directive for rule in rules if not rule.allow]
        if denies:
            reason = (
                "No `deny` rule in the same context overlaps the allowed addresses, so the `allow` "
                "directives change nothing; add `deny all;` after them."
            )
        else:
            reason = "No deny rule was found in the same context; add `deny all;` after the `allow` directives."
        self.add_issue(
            directive=[rule.directive for rule in allows] + denies,
            reason=reason,
        )

    def _report_shadowed(self, rule, shadows, mapped):
        names = ", ".join("`{0}`".format(shadow) for shadow in shadows)
        verb = "matches" if len(shadows) == 1 else "match"
        if mapped:
            where = "IPv4-mapped IPv6 clients are checked against the IPv4 rules, where {0} {1} first".format(
                names, verb
            )
        else:
            where = "{0} {1} those clients first".format(names, verb)
        outcome = "allowed" if shadows[0].allow else "denied"
        self.add_issue(
            severity=gixy.severity.HIGH if not rule.allow else gixy.severity.MEDIUM,
            summary=self.shadowed_allow_summary if rule.allow else self.shadowed_deny_summary,
            description=self.shadowed_description,
            directive=[rule.directive] + [shadow.directive for shadow in shadows],
            reason="`{rule}` never applies: {where}, so they stay {outcome}.".format(
                rule=rule, where=where, outcome=outcome
            ),
        )
