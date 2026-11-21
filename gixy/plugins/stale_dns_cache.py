import re

import tldextract

import gixy
import gixy.core.builtin_variables as builtins
from gixy.core.utils import PASS_DIRECTIVES, enclosing_module
from gixy.core.variable import compile_hash_entry, compile_script
from gixy.directives.directive import MapDirective, is_ipv4, is_ipv6
from gixy.plugins.plugin import Plugin

_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=(), cache_dir=None)
_UNIX_SOCKET_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?unix:", re.IGNORECASE)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _tail(tails):
    tails = [tail for tail in tails if tail is not None]
    return all(tails) if tails else None


class stale_dns_cache(Plugin):
    """
    Insecure example:
        proxy_pass https://example.com;
    """

    summary = "proxy_pass (or another *_pass) may use stale IPs for hostnames that are only resolved at start-up."
    severity = gixy.severity.LOW
    description = (
        "A hostname in proxy_pass or another *_pass, or in an upstream server without 'resolve', "
        "is resolved only at startup, so its IPs can go stale. Use a variable with a resolver, "
        "or upstream 'server ... resolve' (nginx>=1.27.3)."
    )
    help_url = "https://gixy.io/plugins/stale_dns_cache/"
    directives = PASS_DIRECTIVES

    def __init__(self, config):
        super(stale_dns_cache, self).__init__(config)
        self.extract = _EXTRACT
        self.parse_uri_re = re.compile(
            r"^(?P<scheme>[a-z][a-z0-9+.-]*://)?(?P<host>\[[0-9a-fA-F:.]+\]|[^/?#:]+)(?::(?P<port>[0-9]+))?",
            re.IGNORECASE,
        )
        self._groups = {}

    def _needs_dns(self, target, startup=True):
        if _UNIX_SOCKET_RE.match(target):
            return False
        parsed = self.parse_uri_re.match(target)
        host = parsed.group("host") if parsed else target
        if is_ipv6(host) or is_ipv4(host, False):
            return False
        host = host.lower().rstrip(".")
        return not startup or (host not in ("localhost", "ip6-localhost") and not host.endswith(".localhost"))

    def _targets(self, script, seen=(), top=False):
        targets = [""]
        multiple = False
        for index, var in enumerate(script):
            options = var.options
            if (multiple and var.name) or not options or var in seen or (var.name and builtins.is_builtin(var.name)):
                return targets, bool(var.must_startswith("/"))
            expanded = [self._option_values(option, seen + (var,)) for option in options]
            values = list(dict.fromkeys(value for option_values, _ in expanded for value in option_values))
            if not all(isinstance(value, str) for value in values):
                return targets, bool(var.must_startswith("/"))
            targets = [target + value for target in targets for value in values]
            tail = _tail(tail for _, tail in expanded)
            if tail is not None:
                return targets, tail
            multiple = multiple or len(values) > 1
            if multiple and not top and index + 1 < len(script):
                return targets, bool(script[index + 1].must_startswith("/"))
        return targets, None

    def _option_values(self, option, seen):
        if option not in self._values:
            self._values[option] = self._expand(option, seen)
        return self._values[option]

    def _expand(self, option, seen):
        if isinstance(option.value, list):
            expanded = [self._targets(compile_hash_entry(entry) or [], seen) for entry in option.value]
            return [target for targets, _ in expanded for target in targets], _tail(tail for _, tail in expanded)
        if option.depends:
            return self._targets(option.depends, seen)
        return [option.final_value], None

    def _upstream_host(self, target):
        url = self.parse_uri_re.match(target)
        return url.group("host").lower() if url and not url.group("port") else None

    def _socket(self, target, scheme="", bounded=True):
        url = self.parse_uri_re.match(target)
        if not url or not (target[url.end():url.end() + 1] in ("/", "?") or (url.end() == len(target) and bounded)):
            return None
        if url.group("port"):
            port = int(url.group("port"))
        else:
            port = _DEFAULT_PORTS.get((url.group("scheme") or scheme).lower().rstrip(":/"))
        return (url.group("host").lower(), port) if port else None

    def _static_groups(self, directive):
        scope = enclosing_module(directive) or list(directive.parents)[-1]
        if scope in self._groups:
            return self._groups[scope]
        named = {block.args[0].lower() for block in scope.find_recursive("upstream") if len(block.args) == 1}
        groups = self._groups[scope] = {}
        for name in PASS_DIRECTIVES:
            for other in scope.find_recursive(name):
                if isinstance(other, MapDirective):
                    continue
                target = other.args[0] if other.args else ""
                socket = None if "$" in target or _UNIX_SOCKET_RE.match(target) else self._socket(target)
                if socket and socket[0] not in named:
                    groups.setdefault(socket, other)
        return groups

    def audit(self, directive):
        if not getattr(directive, "args", None):
            return

        proxy_target = directive.args[0]

        if _UNIX_SOCKET_RE.match(proxy_target) or not self.parse_uri_re.match(proxy_target):
            return

        self._values = {}
        scheme, sep, rest = proxy_target.partition("://")
        targets, tail = self._targets(compile_script(rest if sep else proxy_target), top=True)

        if not any(self._needs_dns(target, startup="$" not in proxy_target) for target in targets):
            return

        severity = self.severity

        resolver = directive.find_single_directive_in_scope("resolver")

        upstream_hosts = {self._upstream_host(target) for target in targets}
        upstream_directives = []
        found_upstream = False
        found_bad_server = False
        for upstream in directive.find_imperative_directives_in_scope("upstream", True):
            upstream_args = getattr(upstream, "args", None)
            upstream_name = (
                upstream_args[0] if upstream_args and len(upstream_args) == 1 else None
            )
            if upstream_name and upstream_name.lower() in upstream_hosts:
                found_upstream = True
                for child in upstream.children:
                    if child.name != "server":
                        continue

                    if "resolve" in child.args:
                        upstream_resolver = (
                            upstream.some("resolver", flat=False)
                            or upstream.find_single_directive_in_scope("resolver")
                        )
                        if not upstream_resolver:
                            self.add_issue(
                                severity=gixy.severity.MEDIUM,
                                directive=[directive, upstream, child],
                                reason=(
                                    "Upstream uses `server ... resolve`, but no `resolver` is configured in http{} "
                                    "or the upstream block. Dynamic DNS re-resolution will not work as intended."
                                ),
                            )
                            return
                        continue

                    if not self._needs_dns(child.arg(0)):
                        continue

                    found_bad_server = True
                    upstream_directives.append(child)

                    if self.extract(child.arg(0)).suffix:
                        severity = (
                            gixy.severity.MEDIUM
                        )  # Registerable suffix (one way or another)

        if (
            not found_upstream and "$" in proxy_target
        ):  # https://host/$1 is OK, as long as 'host' is not an 'upstream'.
            groups = self._static_groups(directive)
            runtime, shared = [], {}
            for target in targets:
                group = groups.get(self._socket(target, scheme if sep else "", tail is not False))
                if group is None:
                    runtime.append(target)
                elif self._needs_dns(target):
                    shared.setdefault(group, target)
            for group, target in shared.items():
                self.add_issue(
                    severity=gixy.severity.MEDIUM if self.extract(target).suffix else self.severity,
                    directive=[directive, group],
                    reason=(
                        "`{} {}` names the same host and port without variables, so nginx sends this {} "
                        "to the addresses it resolved at startup.".format(group.name, group.args[0], directive.name)
                    ),
                )
            if not resolver and any(self._needs_dns(target, startup=False) for target in runtime):
                self.add_issue(
                    severity=gixy.severity.MEDIUM,
                    directive=directive,
                    reason=(
                        "{} uses variables, but no `resolver` is configured. "
                        "Requests will fail because nginx cannot resolve the upstream "
                        "at runtime.".format(directive.name)
                    ),
                )
            return

        if found_upstream and not found_bad_server:
            return

        if not found_upstream:
            if any(
                target and self.extract(target).suffix for target in targets
            ):  # Registerable suffix (one way or another)
                severity = gixy.severity.MEDIUM

        if resolver:
            upstream_directives.extend([resolver])

        self.add_issue(
            severity=severity,
            directive=[directive] + upstream_directives,
            reason="The {} directive should use a variable for the hostname.".format(directive.name),
        )
