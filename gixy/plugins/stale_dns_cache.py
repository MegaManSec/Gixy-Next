import re

import tldextract

import gixy
import gixy.core.builtin_variables as builtins
from gixy.core.variable import compile_script
from gixy.directives.directive import is_ipv4, is_ipv6
from gixy.plugins.plugin import Plugin

_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=(), cache_dir=None)
_UNIX_SOCKET_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?unix:", re.IGNORECASE)


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
    directives = ["proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass"]

    def __init__(self, config):
        super(stale_dns_cache, self).__init__(config)
        self.extract = _EXTRACT
        self.parse_uri_re = re.compile(
            r"^(?P<scheme>[a-z][a-z0-9+.-]*://)?(?P<host>\[[0-9a-fA-F:.]+\]|[^/?#:]+)(?::(?P<port>[0-9]+))?"
        )

    def _needs_dns(self, target, startup=True):
        if _UNIX_SOCKET_RE.match(target):
            return False
        parsed = self.parse_uri_re.match(target)
        host = parsed.group("host") if parsed else target
        if is_ipv6(host) or is_ipv4(host, False):
            return False
        host = host.lower().rstrip(".")
        return not startup or (host not in ("localhost", "ip6-localhost") and not host.endswith(".localhost"))

    @staticmethod
    def _option_values(option):
        if not isinstance(option.value, list):
            return [option.final_value]
        return [entry.provider.dest_val for entry in option.value]

    def audit(self, directive):
        if not getattr(directive, "args", None):
            return

        proxy_target = directive.args[0]

        if _UNIX_SOCKET_RE.match(proxy_target):
            return

        parsed = self.parse_uri_re.match(proxy_target)
        if not parsed:
            return

        raw_host = parsed.group("host")
        if not raw_host:
            return

        parsed_host_compiled = compile_script(
            raw_host
        )  # proxy_pass $var <- $var may be a variable to an upstream (ugly, but valid).
        parsed_hosts = [""]  # this is fine, just ugly; parsed_hosts are only really used for upstream anyways
        upstream_name_candidates = set()
        for var in parsed_host_compiled:
            if var.name and builtins.is_builtin(var.name):
                break
            values = [value for option in var.options for value in self._option_values(option)]
            if not all(isinstance(value, str) for value in values):
                break
            upstream_name_candidates.update(values)
            parsed_hosts = [host + value for host in parsed_hosts for value in values]
            if len(values) > 1:
                break

        if not any(self._needs_dns(host, startup="$" not in proxy_target) for host in parsed_hosts):
            return

        severity = self.severity

        resolver = directive.find_single_directive_in_scope("resolver")

        upstream_directives = []
        found_upstream = False
        found_bad_server = False
        for upstream in directive.find_imperative_directives_in_scope("upstream", True):
            upstream_args = getattr(upstream, "args", None)
            upstream_name = (
                upstream_args[0] if upstream_args and len(upstream_args) == 1 else None
            )
            if upstream_name and (
                upstream_name in parsed_hosts
                or upstream_name in upstream_name_candidates
            ):
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
            if not resolver:
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
                host and self.extract(host).suffix for host in parsed_hosts
            ):  # Registerable suffix (one way or another)
                severity = gixy.severity.MEDIUM

        if resolver:
            upstream_directives.extend([resolver])

        self.add_issue(
            severity=severity,
            directive=[directive] + upstream_directives,
            reason="The {} directive should use a variable for the hostname.".format(directive.name),
        )
