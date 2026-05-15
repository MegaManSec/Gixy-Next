import re
from urllib.parse import urlparse

import tldextract

import gixy
from gixy.core.regexp import Regexp
from gixy.directives.block import MapBlock
from gixy.directives.directive import AddHeaderDirective, MapDirective
from gixy.plugins.plugin import Plugin

_EXTRACT = tldextract.TLDExtract(
    include_psl_private_domains=True, suffix_list_urls=()
)  # include private domains, because we only care about origin; not domain ownership


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
        # Invalid (and insecure) header, 'referrer' is the wrong spelling.
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
    severity_insecure_origin = gixy.severity.HIGH
    description = "Improve the regular expression to match only correct and trusted referers and origins."
    help_url = "https://gixy.io/plugins/origins/"
    directives = ["if"]
    supports_full_config = True
    options = {"domains": ["*"], "https_only": False, "lower_hostname": True}
    options_help = {
        "domains": 'Comma-separated list of trusted registrable domains. Origins/referers that may match a different domain are flagged as insecure. Use "*" to skip domain allowlisting',
        "https_only": "Boolean. Only allow https scheme in origins/referers when true.",
        "lower_hostname": "Boolean. Normalize hostnames to lowercase prior to validation.",
    }

    def __init__(self, config):
        super(origins, self).__init__(config)
        self.extract = _EXTRACT

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
        if not i or not j:
            return False

        i = i.strip(".").lower()
        j = j.strip(".").lower()

        if i == j:
            return True

        xi = self.extract(i)
        xj = self.extract(j)

        def _top_domain_under_public_suffix(x):
            domain = getattr(x, "domain", None) or ""
            suffix = getattr(x, "suffix", None) or ""
            return f"{domain}.{suffix}" if domain and suffix else None

        ei = _top_domain_under_public_suffix(xi)
        ej = _top_domain_under_public_suffix(xj)

        return ei is not None and ei == ej

    def parse_url(self, url):
        try:
            parsed_url = urlparse(url)
            if not parsed_url.hostname or not parsed_url.scheme:
                # Attempt to fixup the url for the second pass
                # e.g. 'domain.com$', 'google.com/lol', '/lol$'
                # should become 'https://def.comdomain.com', 'https://def.comgoogle.com/lol', and 'https://def.comabc.com/lol'.
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
        except:
            self.invalid_set.add(url)

    def _analyze_and_report(self, pattern, case_sensitive, name, directive):
        self.insecure_set = set()
        self.invalid_set = set()

        severity = (
            self.severity_insecure_origin
            if name == "origin"
            else self.severity_insecure_referer
        )

        regexp = Regexp(pattern, case_sensitive=case_sensitive)
        for candidate_match in regexp.generate("`", anchored=True, max_repeat=5):
            candidate_match = candidate_match.encode("idna").decode()

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
                except:
                    continue
            if self.insecure_set:
                invalids = ", ".join(self.insecure_set).replace("`", "a")
                reason = "Regex matches insecure `{value}` as a valid {name}.".format(
                    value=invalids, name=name
                )
                self.add_issue(directive=directive, reason=reason, severity=severity)

        if self.invalid_set:
            invalids = '", "'.join(self.invalid_set).replace("`", "a")
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
            reason = "Incorrect header `$http_referrer`; use `$http_referer`."
            self.add_issue(
                directive=directive,
                reason=reason,
                severity=self.severity_insecure_origin,
            )
            return

        case_sensitive = directive.operand in ["~", "!~"]
        name = self.directive_type.split("_")[1]
        self._analyze_and_report(directive.value, case_sensitive, name, directive)

    def post_audit(self, root):
        """Analyze map-based CORS allowlists: map $http_origin $var; add_header Access-Control-Allow-Origin $var"""
        # Find add_header directives that set Access-Control-Allow-Origin to a variable
        for node in root.find_recursive("add_header"):
            if not isinstance(node, AddHeaderDirective):
                continue
            if node.header != "access-control-allow-origin":
                continue
            value = node.value.strip().strip("\"'")
            if not value.startswith("$"):
                continue
            dest_var = value.lstrip("$")

            # Find map blocks that populate this variable from $http_origin
            for mb in root.find_recursive("map"):
                if not isinstance(mb, MapBlock):
                    continue
                if getattr(mb, "variable", None) != dest_var:
                    continue
                if getattr(mb, "source", None) != "$http_origin":
                    continue

                # Iterate map entries (including those in includes)
                for md in mb.gather_map_directives(mb.children):
                    if not isinstance(md, MapDirective):
                        continue
                    # Only consider regex map keys
                    if not md.is_regex:
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
