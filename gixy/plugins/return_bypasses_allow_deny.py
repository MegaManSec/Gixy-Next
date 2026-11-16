import re

import gixy
from gixy.core.utils import AUTH_DIRECTIVES, enforced_auth, satisfy_any
from gixy.plugins.plugin import Plugin


class return_bypasses_allow_deny(Plugin):
    """
    Insecure example:
        location / {
            allow 127.0.0.1;
            deny all;
            return 200 "hi";
        }
    """

    summary = "Return directive bypasses access restrictions in the same context."
    severity = gixy.severity.HIGH
    description = (
        "The return directive is executed before allow/deny and the auth modules take "
        "effect in the same context. Serve the response from the content phase instead "
        "(try_files, proxy_pass, root/index); moving the return into a named location "
        "does not help."
    )
    help_url = "https://gixy.io/plugins/return_bypasses_allow_deny/"
    ACCESS_RULES = ("allow", "deny")
    directives = list(ACCESS_RULES) + list(AUTH_DIRECTIVES)
    DENIAL_STATUSES = {"auth_basic": ("401",), "auth_jwt": ("401",), "auth_request": ("401", "403")}

    def __init__(self, config):
        super(return_bypasses_allow_deny, self).__init__(config)
        self._reported_parents = set()
        self._reported_directives = set()

    @staticmethod
    def _is_internal_only_location(node):
        """True for named locations and locations carrying `internal`."""
        return node.name == "location" and (node.path.startswith("@") or node.is_internal)

    @staticmethod
    def _rewrite_reaches(rewrite, location):
        """True when the rewrite's replacement can produce a URI the location matches."""
        literal, variables, _ = rewrite.replace.split("?")[0].partition("$")
        if location.is_regex:
            if variables:
                return True
            try:
                return re.search(location.path, literal, 0 if location.modifier == "~" else re.I) is not None
            except re.error:
                return True
        if variables and location.path.startswith(literal):
            return True
        return literal == location.path if location.modifier == "=" else literal.startswith(location.path)

    @classmethod
    def _reached_only_after_access(cls, node):
        """True for a location only entered by an internal redirect issued after
        the originating location's access phase: a named location, or an
        `internal` location no `rewrite` can send requests into before access
        (one at server level, or with `last` or no flag in a location external
        requests reach)."""
        if not cls._is_internal_only_location(node):
            return False
        if node.path.startswith("@"):
            return True
        scopes = list(node.parents)
        server = next((scope for scope in scopes if scope.name == "server"), scopes[-1])
        for rewrite in server.find_recursive("rewrite"):
            locations = [scope for scope in rewrite.parents if scope.name == "location"]
            if rewrite.redirects or (rewrite.flag == "break" and locations):
                continue
            if any(cls._is_internal_only_location(location) for location in locations):
                continue
            if cls._rewrite_reaches(rewrite, node):
                return False
        return True

    @staticmethod
    def _returns_unhandled_error(directive, denial_statuses=()):
        """True for a `return` of an error status, without a body, that is a
        status the restriction itself answers with, or that the `error_page`
        directives in effect (those of the nearest scope declaring any) do
        not list."""
        if not directive.args or any(directive.args[1:]):
            return False
        code = directive.args[0]
        if not code.isdigit() or int(code) < 400:
            return False
        if code in denial_statuses:
            return True
        for parent in directive.parents:
            error_pages = parent.find("error_page")
            if error_pages:
                return not any(code in error_page.args[:-1] for error_page in error_pages)
        return True

    @staticmethod
    def _serves_no_content(directive):
        """True for a redirect, or a `return` below 400 without body text."""
        if directive.name == "rewrite":
            return True
        code = directive.args[0]
        if not code.isdigit() or 300 <= int(code) < 400:
            return True
        return int(code) < 400 and not any(directive.args[1:])

    @classmethod
    def _access_satisfied_for_all(cls, directive):
        """True when `satisfy any` is in effect and the access rules in effect
        start with `allow all`: the access module admits every client, so the
        auth modules never run."""
        if not satisfy_any(directive.parent):
            return False
        for scope in directive.parents:
            rules = [c for c in scope.children if c.name in cls.ACCESS_RULES]
            if rules:
                return rules[0].name == "allow" and rules[0].args[0] == "all"
        return False

    def _find_descendants_excluding_internal_locations(self, node, name, overrides):
        result = []
        for child in node.children:
            if self._reached_only_after_access(child):
                continue
            if child.name == name:
                result.append(child)
            if getattr(child, "is_block", False) and not any(
                child.some(override, flat=False) for override in overrides
            ):
                result.extend(
                    self._find_descendants_excluding_internal_locations(child, name, overrides)
                )
        return result

    def _bypassing(self, parent, overrides, denial_statuses=()):
        bypassing = [
            d
            for d in self._find_descendants_excluding_internal_locations(
                parent, "return", overrides
            )
            if not self._returns_unhandled_error(d, denial_statuses)
        ]
        bypassing += [
            d
            for d in self._find_descendants_excluding_internal_locations(
                parent, "rewrite", overrides
            )
            if d.redirects
        ]
        return [d for d in bypassing if id(d) not in self._reported_directives]

    def audit(self, directive):
        parent = directive.parent

        if not parent or any(block.name == "stream" for block in directive.parents):
            return

        key = id(parent)
        if key in self._reported_parents:
            return
        self._reported_parents.add(key)

        # `return` and any redirecting rewrite emit their response during the
        # rewrite phase, before the access phase where allow/deny and the auth
        # modules run. (`rewrite ... last|break` with a plain URI replacement
        # keeps processing, so it does not bypass.)
        restrictions = []
        bypassing = []
        rules = [child for child in parent.children if child.name in self.ACCESS_RULES]
        if any(rule.name == "deny" for rule in rules):
            found = self._bypassing(parent, self.ACCESS_RULES, ("403",))
            if found:
                restrictions.append(("`allow`/`deny`", rules))
                bypassing += found
        for name in AUTH_DIRECTIVES:
            auth = parent.some(name, flat=False)
            if auth is None:
                continue
            found = [
                d
                for d in self._bypassing(parent, (name,), self.DENIAL_STATUSES.get(name, ()))
                if name in enforced_auth(d.parent) and not self._access_satisfied_for_all(d)
            ]
            if found:
                restrictions.append(("`{0}`".format(name), [auth]))
                bypassing += found
        if not bypassing:
            return

        unique = []
        for d in bypassing:
            if id(d) not in self._reported_directives:
                self._reported_directives.add(id(d))
                unique.append(d)
        self.add_issue(
            severity=(
                gixy.severity.LOW
                if all(self._serves_no_content(d) for d in unique)
                else gixy.severity.HIGH
            ),
            directive=[d for _, ds in restrictions for d in ds] + unique,
            reason=(
                "{0} cannot restrict responses produced by `return` "
                "or by a redirecting `rewrite`, which run before the access phase.".format(
                    " and ".join(label for label, _ in restrictions)
                )
            ),
        )
