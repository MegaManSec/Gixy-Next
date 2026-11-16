import logging
import re
from urllib.parse import urlparse

import gixy
from gixy.core.regexp import PARSE_ERRORS, Regexp, RegexpTooComplex
from gixy.core.utils import bare_variable_name, registrable_domain, resolve_inherited_list, resolve_variable_chain
from gixy.core.variable import EXTRACT_RE
from gixy.directives.block import MapBlock
from gixy.directives.directive import (
    AddHeaderDirective,
    MapDirective,
    MoreSetHeadersDirective,
    SetDirective,
)
from gixy.plugins.plugin import Plugin

LOG = logging.getLogger(__name__)


class origins(Plugin):
    r"""
    Insecure examples:
        # Insecure referer, allows https://metrika-hacked-yandex.ru/
        if ($http_referer !~ "^https://([^/])+metrika.*yandex\.ru/") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Invalid header, origin cannot contain a path
        if ($http_origin !~ "^https://yandex\.ru/$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Invalid header, 'referrer' is the wrong spelling.
        if ($http_referrer !~ "^https://yandex\.ru/") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Insecure origin header, allows https://sub-yandex.ru
        if ($http_origin !~ "^https://sub.yandex.ru$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Insecure origin header, allows http://sub.yandex.ru (when using --origins-https-only True)
        if ($http_origin !~ "^https?://sub\.yandex\.ru$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
        # Insecure origin header, allows https://yahoo\.com (when using --origins-domains yandex.com)
        if ($http_origin !~ "^https://yahoo\.com$") {
            add_header X-Frame-Options SAMEORIGIN;
        }
    """

    summary = 'Validation regex for "origin" or "referer" matches untrusted domain or invalid value.'
    severity_invalid_header = gixy.severity.LOW
    severity_insecure_referer = gixy.severity.MEDIUM
    severity_reflection = gixy.severity.MEDIUM
    severity_insecure_origin = gixy.severity.HIGH
    description = "Improve the regular expression to match only correct and trusted referers and origins."
    help_url = "https://gixy.io/plugins/origins/"
    directives = ["if"]
    supports_full_config = True
    options = {"domains": ["*"], "https_only": False, "lower_hostname": True}
    options_help = {
        "domains": (
            "Comma-separated list of trusted registrable domains. Origins/referers "
            "that may match a different domain are flagged as insecure. "
            'Use "*" to skip domain allowlisting'
        ),
        "https_only": "Boolean. Only allow https scheme in origins/referers when true.",
        "lower_hostname": "Boolean. Normalize hostnames to lowercase prior to validation.",
    }

    def __init__(self, config):
        super(origins, self).__init__(config)

        self.directive_type = None
        self.insecure_set = set()
        self.invalid_set = set()

        self.allowed_domains = None
        domains = self.config.get("domains")
        if domains and domains[0] and domains[0] != "*":
            self.allowed_domains = tuple(domains)

        self.https_only = bool(self.config.get("https_only"))
        self.lower_hostname = bool(self.config.get("lower_hostname"))
        self.lower_hostname_pattern = re.compile(r"^[a-z0-9.:\[\]-]+$")  # :][ for IPv6

    def same_origin(self, i, j):
        return bool(i and j) and registrable_domain(i) == registrable_domain(j)

    def parse_url(self, url):
        try:
            parsed_url = urlparse(url)
            if not parsed_url.hostname or not parsed_url.scheme:
                # Attempt to fixup the url for the second pass
                # e.g. 'domain.com$', 'google.com/lol', '/lol$'
                # should become 'https://def.comdomain.com',
                # 'https://def.comgoogle.com/lol', and 'https://def.comabc.com/lol'.
                if url[0] == "/":
                    url = "abc.com" + url
                if "://" not in url:
                    url = "https://def.com" + url
                self.insecure_set.add(url)
                return

            if self.https_only and parsed_url.scheme != "https":
                self.insecure_set.add(url)
                return

            if parsed_url.scheme not in {"http", "https"}:
                self.insecure_set.add(url)
                return

            return parsed_url
        except (TypeError, ValueError, IndexError):
            # IndexError: url[0] above on an empty candidate (e.g. generated
            # from a fully-optional pattern like '^(http://mysite.com)?$').
            self.invalid_set.add(url)

    def _analyze(self, pattern, case_sensitive, name):
        self.insecure_set = set()
        self.invalid_set = set()

        try:
            regexp = Regexp(pattern, case_sensitive=case_sensitive)
            candidates = list(regexp.generate("`", anchored=True, max_repeat=5))
        except PARSE_ERRORS as e:
            LOG.warning("Failed to parse regex: %s (%s)", pattern, str(e))
            return False
        except RegexpTooComplex as e:
            LOG.warning("Regex too complex to analyze: %s (%s)", pattern, str(e))
            return False
        for candidate_match in candidates:
            try:
                candidate_match = candidate_match.encode("idna").decode()
            except UnicodeError:
                # Generated candidate isn't a valid DNS string (empty label,
                # over-long label, etc., per RFC 3490). Python 3.11+ rejects
                # these strictly; older versions tolerated them. Keep the raw
                # value — downstream sanitisation and parse_url handle it.
                pass

            candidate_match = re.sub(
                r'[^A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=`^%"]', "`", candidate_match
            )

            base_mutant_raw = candidate_match.lstrip("^").rstrip("$")
            base_mutant_parsed = self.parse_url(base_mutant_raw)
            if not base_mutant_parsed:
                continue
            base_hostname = base_mutant_parsed.hostname

            suffix_mutant_raw = candidate_match.lstrip("^")
            if suffix_mutant_raw.endswith("$"):
                suffix_mutant_raw = suffix_mutant_raw.rstrip("$")
            else:
                suffix_mutant_raw += ".evil.com"
            suffix_mutant_parsed = self.parse_url(suffix_mutant_raw)
            if not suffix_mutant_parsed:
                continue
            suffix_hostname = suffix_mutant_parsed.hostname
            if not self.same_origin(base_hostname, suffix_hostname):
                self.insecure_set.add(suffix_mutant_raw)
                continue

            prefix_mutant_raw = candidate_match.rstrip("$")
            if prefix_mutant_raw.startswith("^"):
                prefix_mutant_raw = prefix_mutant_raw.lstrip("^")
            else:
                if name == "referer":
                    prefix_mutant_raw = "http://evil.com/?" + prefix_mutant_raw
                else:
                    prefix_mutant_raw = "http://evil.com" + prefix_mutant_raw
            prefix_mutant_parsed = self.parse_url(prefix_mutant_raw)
            if not prefix_mutant_parsed:
                continue
            prefix_hostname = prefix_mutant_parsed.hostname
            if not self.same_origin(base_hostname, prefix_hostname):
                self.insecure_set.add(prefix_mutant_raw)
                continue

            base_hostname_filled = base_hostname.replace("`", "a")
            suffix_hostname_filled = suffix_hostname.replace("`", "b")
            prefix_hostname_filled = prefix_hostname.replace("`", "c")

            base_mutant_raw_filled = base_mutant_raw.replace("`", "a")
            suffix_mutant_raw_filled = suffix_mutant_raw.replace("`", "b")
            prefix_mutant_raw_filled = prefix_mutant_raw.replace("`", "c")

            if not self.same_origin(base_hostname, base_hostname_filled):
                self.insecure_set.add(base_mutant_raw_filled)
                continue

            if not self.same_origin(base_hostname_filled, suffix_hostname_filled):
                self.insecure_set.add(suffix_mutant_raw_filled)
                continue

            if not self.same_origin(base_hostname_filled, prefix_hostname_filled):
                self.insecure_set.add(prefix_mutant_raw_filled)
                continue

            if self.allowed_domains:
                if not any(
                    self.same_origin(base_hostname_filled, d)
                    for d in self.allowed_domains
                ):
                    self.insecure_set.add(base_mutant_raw_filled)
                    continue
                if not any(
                    self.same_origin(suffix_hostname_filled, d)
                    for d in self.allowed_domains
                ):
                    self.insecure_set.add(suffix_mutant_raw_filled)
                    continue
                if not any(
                    self.same_origin(prefix_hostname_filled, d)
                    for d in self.allowed_domains
                ):
                    self.insecure_set.add(prefix_mutant_raw_filled)
                    continue

            if self.lower_hostname:
                if not self.lower_hostname_pattern.fullmatch(
                    base_mutant_parsed.netloc.replace("`", "a")
                ):
                    self.invalid_set.add(base_mutant_raw_filled)
                    continue
                if not self.lower_hostname_pattern.fullmatch(
                    suffix_mutant_parsed.netloc.replace("`", "b")
                ):
                    self.invalid_set.add(suffix_mutant_raw_filled)
                    continue
                if not self.lower_hostname_pattern.fullmatch(
                    prefix_mutant_parsed.netloc.replace("`", "c")
                ):
                    self.invalid_set.add(prefix_mutant_raw_filled)
                    continue

            if name == "origin":
                if (
                    len(
                        base_mutant_parsed.path
                        + base_mutant_parsed.params
                        + base_mutant_parsed.query
                        + base_mutant_parsed.fragment
                    )
                    > 0
                ):
                    self.invalid_set.add(base_mutant_raw_filled)
                    continue
                if (
                    len(
                        suffix_mutant_parsed.path
                        + suffix_mutant_parsed.params
                        + suffix_mutant_parsed.query
                        + suffix_mutant_parsed.fragment
                    )
                    > 0
                ):
                    self.invalid_set.add(suffix_mutant_raw_filled)
                    continue
                if (
                    len(
                        prefix_mutant_parsed.path
                        + prefix_mutant_parsed.params
                        + prefix_mutant_parsed.query
                        + prefix_mutant_parsed.fragment
                    )
                    > 0
                ):
                    self.invalid_set.add(prefix_mutant_raw_filled)
                    continue

        if self.insecure_set:
            for url in self.insecure_set.copy():
                try:
                    parsed_url = urlparse(url)
                    if not parsed_url.scheme or not parsed_url.hostname:
                        self.invalid_set.add(url)
                        self.insecure_set.remove(url)
                        continue
                    if name == "origin":
                        if (
                            len(
                                parsed_url.path
                                + parsed_url.params
                                + parsed_url.query
                                + parsed_url.fragment
                            )
                            > 0
                        ):
                            self.invalid_set.add(url)
                            self.insecure_set.remove(url)
                except (TypeError, ValueError):
                    continue
        return True

    def _analyze_and_report(self, pattern, case_sensitive, name, directive):
        if not self._analyze(pattern, case_sensitive, name):
            return

        severity = (
            self.severity_insecure_origin
            if name == "origin"
            else self.severity_insecure_referer
        )

        if self.insecure_set:
            invalids = ", ".join(sorted(self.insecure_set)).replace("`", "a")
            reason = "Regex matches insecure `{value}` as a valid {name}.".format(
                value=invalids, name=name
            )
            self.add_issue(directive=directive, reason=reason, severity=severity)

        if self.invalid_set:
            invalids = '", "'.join(sorted(self.invalid_set)).replace("`", "a")
            reason = 'Regex matches invalid "{value}" as a valid {name}.'.format(
                value=invalids, name=name
            )
            if name == "origin":
                reason += " Origin headers must be in the format <scheme>://<hostname>[:port] with no path."
            else:
                reason += " Referer headers should use absolute URLs including a scheme and hostname."
            if self.lower_hostname:
                reason += " Scheme and hostname should be lowercase."
            self.add_issue(
                directive=directive,
                reason=reason,
                severity=self.severity_invalid_header,
            )

    def audit(self, directive):
        self.directive_type = directive.variable

        if directive.operand not in ["~", "~*", "!~", "!~*"]:
            return

        if self.directive_type not in [
            "$http_referer",
            "$http_origin",
            "$http_referrer",
        ]:
            return

        if self.directive_type == "$http_referrer":
            reason = (
                "Incorrect header `$http_referrer`; use `$http_referer`. "
                "Browsers send `Referer`, so this check never sees it."
            )
            self.add_issue(
                directive=directive,
                reason=reason,
                severity=self.severity_invalid_header,
            )
            return

        case_sensitive = directive.operand in ["~", "!~"]
        name = self.directive_type.split("_")[1]
        self._analyze_and_report(directive.value, case_sensitive, name, directive)

    @staticmethod
    def _is_origin_reflection(value):
        """True if a (quote-stripped) value is a bare reflection of $http_origin."""
        return value.lstrip("$").strip("{}").lower() == "http_origin"

    def _report_reflection(self, node, hops=()):
        """Flag unconditional reflection of the request Origin into Access-Control-Allow-Origin:
        HIGH when the response also allows credentials, MEDIUM otherwise."""
        credentials = self._allows_credentials(node)
        reason = (
            "Reflecting `$http_origin` into `Access-Control-Allow-Origin` allows any origin to pass the CORS "
            "check{0}. Echo only origins from a trusted allowlist."
        ).format(", and the response allows credentials" if credentials else "")
        self.add_issue(
            directive=[*hops, node],
            reason=reason,
            severity=self.severity_insecure_origin if credentials else self.severity_reflection,
        )

    def _allows_credentials(self, node):
        """True when `Access-Control-Allow-Credentials: true` is also set on a response `node`
        adds its header to: in its block or any block below it that still inherits `node`,
        by the `add_header` list in effect there or a `more_set_headers` there or above."""
        for block in self._blocks_below(node.parent):
            headers = resolve_inherited_list(block, "add_header", "add_header_inherit")
            headers += [msh for scope in (block, *block.parents) for msh in scope.find("more_set_headers")]
            if node in headers and any(
                value.strip().strip("\"'") == "true"
                for _, value in self._header_directives(headers, "access-control-allow-credentials")
            ):
                return True
        return False

    @classmethod
    def _blocks_below(cls, block):
        yield block
        for child in block.children:
            if child.is_block:
                yield from cls._blocks_below(child)

    def _has_origin_allowlist(self, directive):
        for parent in directive.parents:
            if parent.name != "if" or not self._is_origin_reflection(parent.variable or ""):
                continue
            # Positive regex guards that pass audit()'s checks restrict reflection
            # to an allowlist; negative matches and unrelated conditions do not.
            if parent.operand in ("~", "~*"):
                analyzed = self._analyze(parent.value, parent.operand == "~", "origin")
                if analyzed and not (self.insecure_set or self.invalid_set):
                    return True
            if (
                parent.operand == "="
                and parent.value.startswith(("http://", "https://"))
                and "$" not in parent.value
            ):
                return True
        return self._has_origin_guard(directive)

    def _has_origin_guard(self, directive):
        """An `if` in the serving location or its server that returns for every origin outside an allowlist."""
        scopes = [
            next((parent for parent in directive.parents if parent.name == name), None)
            for name in ("location", "server")
        ]
        for scope in filter(None, scopes):
            if scope.name == "location" and scope.find_recursive("location"):
                continue
            for block in scope.children:
                if block.name != "if" or not block.variable or not block.find("return"):
                    continue
                if not self._is_origin_reflection(block.variable):
                    if self._origin_flag_rejects(block):
                        return True
                    continue
                if block.operand in ("!~", "!~*"):
                    analyzed = self._analyze(block.value, block.operand == "!~", "origin")
                    if analyzed and not (self.insecure_set or self.invalid_set):
                        return True
                if (
                    block.operand == "!="
                    and block.value.startswith(("http://", "https://"))
                    and "$" not in block.value
                ):
                    return True
        return False

    def _origin_flag_rejects(self, block):
        """`if ($flag = X) { return .. }` where `$flag` is a map of $http_origin whose `default`
        is X and whose regex keys pass the checks."""
        if block.operand not in ("=", "!="):
            return False

        def rejects(value):
            return (value.strip("\"'") == block.value) == (block.operand == "=")

        name = bare_variable_name(block.variable)
        for mb in self._root.find_recursive("map"):
            if not isinstance(mb, MapBlock) or mb.variable != name or not self._is_origin_reflection(mb.source):
                continue
            entries = mb.entries
            if not rejects(next((md.dest_val for md in entries if md.src_val == "default"), "")):
                return False
            for md in entries:
                if not md.is_regex or rejects(md.dest_val):
                    continue
                analyzed = self._analyze(md.regex.source, md.regex.case_sensitive, "origin")
                if not analyzed or self.insecure_set or self.invalid_set:
                    return False
            return True
        return False

    @staticmethod
    def _header_directives(directives, header):
        """(directive, value) for every add_header/more_set_headers among `directives` that sets `header`."""
        for node in directives:
            if not isinstance(node, (AddHeaderDirective, MoreSetHeadersDirective)):
                continue
            for name, value in node.headers.items():
                if name.strip().lower() == header:
                    yield node, value

    @staticmethod
    def _sets_in_scope(root, node):
        """`set` directives that can run for a request the header directive `node` applies to.

        Inside a location: the location chain and the enclosing server, flattened
        through `if` blocks. At server level: every `set` in that server, since the
        header is inherited into its locations. Above that: the whole configuration.
        """
        chain = []
        server = None
        for block in node.parents:
            chain.append(block)
            if block.name == "server":
                server = block
                break
        if server is None:
            scope = root.find_recursive("set")
        elif any(block.name == "location" for block in chain):
            scope = (sd for block in chain for sd in block.find("set", flat=True))
        else:
            scope = server.find_recursive("set")
        return list({id(sd): sd for sd in scope if isinstance(sd, SetDirective)}.values())

    @staticmethod
    def _source_variables(mb):
        return {match.group(1).strip("{}").lower() for match in EXTRACT_RE.finditer(mb.source)}

    @staticmethod
    def _origin_copies(root):
        """`http_origin` plus the variables whose every `set` copies it, directly or through such a copy."""
        values = {}
        for sd in root.find_recursive("set"):
            if isinstance(sd, SetDirective):
                values.setdefault(sd.variable, set()).add(bare_variable_name(sd.value))
        copies = {"http_origin"}
        while True:
            found = {name for name, assigned in values.items() if name not in copies and assigned <= copies}
            if not found:
                return copies
            copies |= found

    @staticmethod
    def _matches_empty(pattern, case_sensitive):
        try:
            candidates = Regexp(pattern, case_sensitive=case_sensitive).generate("`", anchored=True, max_repeat=5)
            return any(candidate.lstrip("^").rstrip("$") == "" for candidate in candidates)
        except (*PARSE_ERRORS, RegexpTooComplex):
            return False

    def _origin_assignments(self, root, sets, name):
        """Unguarded `set $name ...` directives, `default` entries of maps keyed on $http_origin,
        and every entry of maps keyed on variables unrelated to the Origin."""
        for sd in sets:
            if sd.variable != name or self._has_origin_allowlist(sd):
                continue
            yield sd, sd.value
        maps = [mb for mb in root.find_recursive("map") if isinstance(mb, MapBlock)]
        copies = self._origin_copies(root)
        origin_keyed = {mb.variable for mb in maps if self._source_variables(mb) & copies}
        for mb in maps:
            if mb.variable != name:
                continue
            sources = self._source_variables(mb)
            if sources & origin_keyed:
                continue
            keyed_on_origin = bool(sources & copies)
            for md in mb.entries:
                # A literal key (`https://trusted.example $http_origin;`) is an
                # exact-match allowlist, so only `default` reflects unconditionally.
                if keyed_on_origin and (md.is_regex or md.src_val != "default"):
                    continue
                if not md.is_regex and md.src_val != "default" and bare_variable_name(md.dest_val) in sources:
                    continue
                yield md, md.dest_val

    def post_audit(self, root):
        """Analyze CORS allowlists: map/set $http_origin -> $var; add_header Access-Control-Allow-Origin $var"""
        self._root = root
        cors_variables = set()
        headers = root.find_recursive("add_header") + root.find_recursive("more_set_headers")
        for node, value in self._header_directives(headers, "access-control-allow-origin"):
            value = value.strip().strip("\"'")
            dest_var = bare_variable_name(value)
            cors_variables.add(dest_var)
            if self._has_origin_allowlist(node):
                continue
            if not value.startswith("$"):
                continue

            # add_header Access-Control-Allow-Origin $http_origin; -> reflects every origin
            if self._is_origin_reflection(value):
                self._report_reflection(node)
                continue

            if dest_var is None:
                continue

            # set $var $http_origin; add_header ... $var; -> indirect reflection,
            # followed through chains of bare-variable set/map-default hops
            sets = self._sets_in_scope(root, node)
            for hops, assigned in resolve_variable_chain(
                dest_var, lambda name: self._origin_assignments(root, sets, name)
            ):
                cors_variables.add(bare_variable_name(assigned))
                if self._is_origin_reflection(assigned.strip().strip("\"'")):
                    self._report_reflection(node, reversed(hops))

            # Find map blocks that populate this variable from $http_origin
            for mb in root.find_recursive("map"):
                if not isinstance(mb, MapBlock):
                    continue
                if getattr(mb, "variable", None) != dest_var:
                    continue
                if not self._is_origin_reflection(mb.source):
                    continue

                # Iterate map entries (including those in includes)
                for md in mb.gather_map_directives(mb.children):
                    if not isinstance(md, MapDirective) or not md.is_regex:
                        continue
                    # Empty or fixed outputs do not reflect the matching origin.
                    if "$" not in (md.dest_val or ""):
                        continue
                    src = md.src_val or ""
                    # Determine case sensitivity and pattern
                    if src.startswith("~*"):
                        pattern = src[2:]
                        cs = False
                    elif src.startswith("~"):
                        pattern = src[1:]
                        cs = True
                    else:
                        continue
                    # Analyze as origin regex
                    self._analyze_and_report(pattern, cs, "origin", [md, node])

        for mb in root.find_recursive("map"):
            if not isinstance(mb, MapBlock) or mb.variable in cors_variables:
                continue
            if not self._is_origin_reflection(mb.source):
                continue
            for md in mb.gather_map_directives(mb.children):
                if not isinstance(md, MapDirective) or not md.is_regex:
                    continue
                if re.search(r"\$[1-9]", md.dest_val or "") or self._matches_empty(
                    md.regex.source, md.regex.case_sensitive
                ):
                    continue
                self._analyze_and_report(md.regex.source, md.regex.case_sensitive, "origin", [md])
