import re
from itertools import takewhile

import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import Regexp
from gixy.core.utils import AUTH_DIRECTIVES
from gixy.core.variable import EXTRACT_RE
from gixy.directives.block import GeoBlock, IfBlock, LocationBlock, MapBlock
from gixy.plugins.plugin import Plugin

LITERAL_PATH_DIRECTIVES = frozenset((
    "error_log",
    "client_body_temp_path",
    "proxy_temp_path",
    "fastcgi_temp_path",
    "uwsgi_temp_path",
    "scgi_temp_path",
    "proxy_cache_path",
    "fastcgi_cache_path",
    "uwsgi_cache_path",
    "scgi_cache_path",
))
LIMIT_ZONE_DIRECTIVES = ("limit_req_zone", "limit_conn_zone")
DENYING_RETURN_CODES = frozenset(("401", "403", "444"))

_PCRE_QUOTE_RE = re.compile(r"(?<!\\)((?:\\\\)*)\\Q")


def _variables(text):
    return [match for match in EXTRACT_RE.finditer(text) if not match.group(1).strip("{}").isdigit()]


def _variable_in(text):
    variables = _variables(text)
    return variables[0].group(0) if variables else None


def _variable_names(text):
    return {match.group(1).strip("{}").lower() for match in _variables(text)}


def _required_parts(op, av):
    if op in (sre_parse.SUBPATTERN, sre_parse.ASSERT):
        return [av[-1]]
    if op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT) and av[0] >= 1:
        return [av[2]]
    return []


def _dead_variable(seq):
    for index, (op, av) in enumerate(seq):
        if op == sre_parse.AT and av == sre_parse.AT_END:
            literals = takewhile(lambda token: token[0] == sre_parse.LITERAL, seq[index + 1:])
            variables = _variables("$" + "".join(chr(code) for _, code in literals))
            if variables and variables[0].start() == 0:
                return variables[0].group(0)
        elif op == sre_parse.BRANCH:
            dead = [_dead_variable(list(alternative)) for alternative in av[1]]
            if all(dead):
                return dead[0]
        for part in _required_parts(op, av):
            found = _dead_variable(list(part))
            if found:
                return found
    return None


def _regex_variable(pattern):
    if _PCRE_QUOTE_RE.search(pattern):
        return None
    try:
        return _dead_variable(list(Regexp(pattern).parsed))
    except (sre_parse.error, OverflowError, RecursionError):
        return None


def _restricts_access(block):
    for child in block.children:
        if child.name == "deny" or (child.is_block and _restricts_access(child)):
            return True
        if not child.args:
            continue
        if child.name in AUTH_DIRECTIVES and child.args[0] != "off":
            return True
        if child.name == "return" and child.args[0] in DENYING_RETURN_CODES:
            return True
    return False


class non_expanding_variable(Plugin):
    """
    Insecure example:
        geo $limit_key {
            default $binary_remote_addr;
        }
        limit_req_zone $limit_key zone=per_ip:10m rate=10r/s;
    """

    summary = "Variable used where NGINX does not expand variables."
    severity = gixy.severity.MEDIUM
    description = (
        "NGINX expands variables in some directive arguments but not others. In geo and "
        "split_clients values, location prefixes, server_name and map keys, the auth_request "
        "URI, and paths such as error_log, a variable is literal text. In a regular expression, "
        "`$name` is an end-of-string anchor followed by `name`, which can never match."
    )
    help_url = "https://gixy.io/plugins/non_expanding_variable/"
    directives = [
        "geo", "split_clients", "map", "location", "if", "server_name", "rewrite", "auth_request",
    ] + sorted(LITERAL_PATH_DIRECTIVES)

    def audit(self, directive):
        if directive.name in LITERAL_PATH_DIRECTIVES:
            self._audit_path(directive)
        elif isinstance(directive, GeoBlock):
            self._audit_geo(directive)
        elif directive.name == "split_clients":
            self._audit_split_clients(directive)
        elif isinstance(directive, MapBlock):
            self._audit_map(directive)
        elif isinstance(directive, LocationBlock):
            self._audit_location(directive)
        elif isinstance(directive, IfBlock):
            self._audit_if(directive)
        elif directive.name == "server_name":
            self._audit_server_name(directive)
        elif directive.name == "rewrite":
            self._audit_rewrite(directive)
        elif directive.name == "auth_request":
            self._audit_auth_request(directive)

    def _audit_path(self, directive):
        variable = directive.args and _variable_in(directive.args[0])
        if variable:
            self.add_issue(
                directive=directive,
                severity=gixy.severity.LOW,
                reason="`{0}` uses the path `{1}` as written; NGINX does not expand `{2}` there.".format(
                    directive.name, directive.args[0], variable
                ),
            )

    def _audit_geo(self, block):
        entries = block.gather_geo_directives(block.children)
        self._audit_values(block, block.variable, [entry.dest_val for entry in entries if entry.dest_val])

    def _audit_split_clients(self, block):
        if len(block.args) == 2:
            values = [entry.args[0] for entry in block.children if entry.args]
            self._audit_values(block, block.args[1].lstrip("$").lower(), values)

    def _audit_values(self, block, variable, values):
        value = next((value for value in values if _variable_in(value)), None)
        if value is None:
            return
        reason = "`{0}` stores `{1}` as literal text, so every client it applies to gets that same value.".format(
            block.name, value
        )
        zones = self._constant_limit_zones(block, variable)
        if zones:
            reason += " `{0}` keys on it, so those clients share one bucket.".format(zones[0].name)
        self.add_issue(
            directive=[block] + zones,
            severity=gixy.severity.HIGH if zones else self.severity,
            reason=reason,
        )

    def _constant_limit_zones(self, block, variable):
        root = block
        while root.parent:
            root = root.parent
        maps = [found for found in root.find_recursive("map") if isinstance(found, MapBlock)]
        literal = {variable}
        grew = True
        while grew:
            grew = False
            for map_block in maps:
                if map_block.variable in literal:
                    continue
                entries = map_block.gather_map_directives(map_block.children)
                names = [_variable_names(entry.dest_val) for entry in entries if entry.dest_val]
                names = [found for found in names if found]
                if names and all(found <= literal for found in names):
                    literal.add(map_block.variable)
                    grew = True
        zones = []
        for name in LIMIT_ZONE_DIRECTIVES:
            for zone in root.find_recursive(name):
                keys = _variable_names(zone.args[0]) if zone.args else set()
                if keys and keys <= literal:
                    zones.append(zone)
        return zones

    def _audit_map(self, block):
        for entry in block.gather_map_directives(block.children):
            if entry.is_regex:
                variable = _regex_variable(entry.regex.source)
                if variable:
                    self._report_regex([block, entry], variable, "this map entry never matches")
                    return
                continue
            variable = _variable_in(entry.src_val)
            if variable:
                self.add_issue(
                    directive=[block, entry],
                    reason="The map key `{0}` matches literal text; NGINX does not expand `{1}` in keys.".format(
                        entry.src_val, variable
                    ),
                )
                return

    def _audit_location(self, location):
        if location.is_regex:
            variable = _regex_variable(location.path)
            if variable:
                self._report_regex(location, variable, "the location never matches", guards=True)
            return
        if location.modifier is None and location.path.startswith(("@", "$")):
            return
        variable = _variable_in(location.path)
        if not variable:
            return
        restricted = _restricts_access(location)
        reason = "The location matches the literal text `{0}`; NGINX does not expand `{1}` there.".format(
            location.path, variable
        )
        if restricted:
            reason += " Its access control never applies to the paths it was meant for."
        self.add_issue(
            directive=location,
            severity=gixy.severity.HIGH if restricted else self.severity,
            reason=reason,
        )

    def _audit_if(self, block):
        variable = block.is_regex and block.value and _regex_variable(block.value)
        if not variable:
            return
        if block.operand.startswith("!"):
            self._report_regex(block, variable, "the condition always matches")
        else:
            self._report_regex(block, variable, "the condition never matches", guards=True)

    def _audit_server_name(self, directive):
        for name in directive.args:
            if name.lower() == "$hostname":
                continue
            if name.startswith("~"):
                variable = _regex_variable(name[1:])
                if variable:
                    self._report_regex(directive, variable, "this server name never matches")
                    return
                continue
            variable = _variable_in(name)
            if variable:
                self.add_issue(
                    directive=directive,
                    reason="`server_name` matches the literal host `{0}`; NGINX does not expand `{1}` there.".format(
                        name, variable
                    ),
                )
                return

    def _audit_rewrite(self, directive):
        variable = directive.args and _regex_variable(directive.args[0])
        if variable:
            self._report_regex(directive, variable, "the rewrite never applies")

    def _audit_auth_request(self, directive):
        uri = directive.args[0] if directive.args else "off"
        variable = uri != "off" and _variable_in(uri)
        if variable:
            self.add_issue(
                directive=directive,
                reason="`auth_request` sends its subrequest to the literal URI `{0}`; NGINX does not expand "
                "`{1}` there.".format(uri, variable),
            )

    def _report_regex(self, directive, variable, consequence, guards=False):
        restricted = guards and _restricts_access(directive)
        reason = "`{0}` in this regex is an end-of-string anchor followed by `{1}`, not a variable, so {2}.".format(
            variable, variable.strip("${}"), consequence
        )
        if restricted:
            reason += " Its access control never applies."
        self.add_issue(
            directive=directive,
            severity=gixy.severity.HIGH if restricted else self.severity,
            reason=reason,
        )
