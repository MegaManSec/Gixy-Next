import re

import tldextract

import gixy
import gixy.core.builtin_variables as builtins
from gixy.core.variable import compile_script
from gixy.directives.directive import is_ipv4, is_ipv6
from gixy.plugins.plugin import Plugin

_EXTRACT = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())


class stale_dns_cache(Plugin):
    """
    Insecure example:
        proxy_pass https://example.com;
    """

    summary = "proxy_pass may use stale IP addresses for hostnames that are only resolved at start-up."
    severity = gixy.severity.LOW
    description = (
        "Using proxy_pass with a static hostname (or an upstream with hostname servers without 'resolve') results in DNS "
        "resolution only at startup, risking proxying to stale IPs. Use a variable in proxy_pass (resolver-based), or "
        "use upstream 'server ... resolve' (nginx>=1.27.3) so TTLs are respected."
    )
    help_url = "https://gixy.io/plugins/stale_dns_cache/"
    directives = ["proxy_pass"]

    def __init__(self, config):
        super(stale_dns_cache, self).__init__(config)
        self.extract = _EXTRACT
        self.parse_uri_re = re.compile(
            r"^(?P<scheme>[a-z][a-z0-9+.-]*://)?(?P<host>\[[0-9a-fA-F:.]+\]|[^/?#:]+)(?::(?P<port>[0-9]+))?"
        )

    def audit(self, directive):
        if not getattr(directive, "args", None):
            return

        proxy_target = directive.args[0]

        if "unix:" in proxy_target:
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
        parsed_host = ""  # this is fine, just ugly; parsed_host is only really used for upstream anyways
        upstream_name_candidates = set()
        for var in parsed_host_compiled:
            if var.name and builtins.is_builtin(var.name):
                break
            if isinstance(var.final_value, str):
                upstream_name_candidates.add(var.final_value)
                parsed_host += var.final_value
            else:
                break

        if is_ipv6(parsed_host) or is_ipv4(parsed_host, False):
            return

        h = parsed_host.lower().rstrip(".")
        if h in ("localhost", "ip6-localhost") or h.endswith(".localhost"):
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
                upstream_name == parsed_host
                or upstream_name in upstream_name_candidates
            ):
                found_upstream = True
                for child in upstream.children:
                    if child.name != "server":
                        continue

                    if "resolve" in child.args:
                        if not resolver:
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

                    # No 'resolve' -> stale DNS risk if this server target is a hostname

                    if "unix:" in child.args[0]:
                        continue

                    parsed_upstream_server = self.parse_uri_re.match(child.args[0])
                    if not parsed_upstream_server:
                        continue

                    parsed_upstream_host = parsed_upstream_server.group("host")
                    if is_ipv6(parsed_upstream_host) or is_ipv4(
                        parsed_upstream_host, False
                    ):
                        continue

                    found_bad_server = True
                    upstream_directives.append(child)

                    if self.extract(parsed_upstream_host).suffix:
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
                    reason="proxy_pass uses variables, but no `resolver` is configured. Requests will fail because nginx cannot resolve the upstream at runtime.",
                )
            return

        if found_upstream and not found_bad_server:
            return

        if not found_upstream:
            if (
                parsed_host and self.extract(parsed_host).suffix
            ):  # Registerable suffix (one way or another)
                severity = gixy.severity.MEDIUM

        if resolver:
            upstream_directives.extend([resolver])

        self.add_issue(
            severity=severity,
            directive=[directive] + upstream_directives,
            reason="The proxy_pass directive should use a variable for the hostname.",
        )
