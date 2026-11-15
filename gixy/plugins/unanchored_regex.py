import gixy
import gixy.core.sre_parse.sre_parse as sre_parse
from gixy.core.regexp import Regexp
from gixy.directives.block import IfBlock, LocationBlock, MapBlock
from gixy.plugins.plugin import Plugin

URI_VARIABLES = frozenset(("$uri", "$document_uri", "$request_uri"))
LOGGING_DIRECTIVES = frozenset(("access_log", "log_not_found"))


def _rejects(directive):
    if directive.name in ("deny", "internal"):
        return True
    return directive.name == "return" and bool(directive.args) and directive.args[0].isdigit() and (
        int(directive.args[0]) >= 400
    )


def _any_characters(seq):
    for op, av in seq:
        if op in (sre_parse.ANY, sre_parse.ANY_ALL):
            continue
        if op == sre_parse.SUBPATTERN:
            body = av[-1]
        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT, sre_parse.POSSESSIVE_REPEAT):
            body = av[2]
        else:
            return False
        if not _any_characters(list(body)):
            return False
    return True


def _over_matches(regexp):
    if not regexp.needs_anchor():
        return False
    try:
        parsed = regexp.parsed
    except Exception:
        return True
    return parsed.getwidth()[0] > 1 or not _any_characters(list(parsed))


def _leading_literal(seq):
    literal = ""
    for index, (op, av) in enumerate(seq):
        if op != sre_parse.LITERAL:
            return literal, seq[index:]
        literal += chr(av)
    return literal, []


def _matches_empty(seq):
    for op, av in seq:
        if op == sre_parse.SUBPATTERN:
            empty = _matches_empty(list(av[-1]))
        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT, sre_parse.POSSESSIVE_REPEAT):
            empty = av[0] == 0 or _matches_empty(list(av[2]))
        elif op == sre_parse.BRANCH:
            empty = any(_matches_empty(list(branch)) for branch in av[1])
        else:
            empty = False
        if not empty:
            return False
    return True


def _location_prefix(location):
    if location.modifier in (None, "=", "^~"):
        return location.path
    if location.modifier == "~":
        try:
            seq = list(Regexp(location.path).parsed)
        except Exception:
            return ""
        if seq and seq[0] in ((sre_parse.AT, sre_parse.AT_BEGINNING), (sre_parse.AT, sre_parse.AT_BEGINNING_STRING)):
            return _leading_literal(seq[1:])[0]
    return ""


def _prefix_pinned(rewrite, regexp):
    try:
        literal, rest = _leading_literal(list(regexp.parsed))
    except Exception:
        return False
    if not literal or not _matches_empty(rest):
        return False
    location = next((parent for parent in rewrite.parents if isinstance(parent, LocationBlock)), None)
    return (
        location is not None
        and location.some("rewrite") is rewrite
        and _location_prefix(location).startswith(literal)
    )


def _only_sets(block):
    return bool(block.children) and all(child.name == "set" for child in block.children)


def _only_rejects(block):
    rejects = False
    for child in block.children:
        if _rejects(child):
            rejects = True
        elif child.name not in LOGGING_DIRECTIVES:
            return False
    return rejects


class unanchored_regex(Plugin):
    r"""
    Insecure example:
        location ~ \.php {

        }
    """

    summary = "Regular expression without anchors matches anywhere in the input."
    severity = gixy.severity.LOW
    description = (
        "A regular expression without anchors matches its pattern anywhere in the request URI "
        "or host name, so it also applies to requests it was not written for."
    )
    help_url = "https://gixy.io/plugins/unanchored_regex/"
    directives = ["location", "if", "map", "rewrite", "server_name"]

    def audit(self, directive):
        if isinstance(directive, LocationBlock):
            if directive.is_regex and not _only_rejects(directive):
                if _over_matches(Regexp(directive.path, case_sensitive=directive.modifier == "~")):
                    self._report(directive)
        elif isinstance(directive, IfBlock):
            self._audit_if(directive)
        elif isinstance(directive, MapBlock):
            if directive.source in URI_VARIABLES:
                for entry in directive.gather_map_directives(directive.children):
                    if entry.regex is not None and _over_matches(entry.regex):
                        self._report([directive, entry])
        elif directive.name == "rewrite":
            if directive.args:
                regexp = Regexp(directive.args[0])
                if _over_matches(regexp) and not _prefix_pinned(directive, regexp):
                    self._report(directive)
        elif directive.name == "server_name":
            for name in directive.args:
                if name.startswith("~") and _over_matches(Regexp(name[1:])):
                    self._report(directive)
                    return

    def _audit_if(self, block):
        if not block.is_regex or block.variable not in URI_VARIABLES:
            return
        negated = block.operand.startswith("!")
        if not negated and (_only_rejects(block) or _only_sets(block)):
            return
        if _over_matches(Regexp(block.value, case_sensitive=block.operand in ("~", "!~"))):
            self._report(block)

    def _report(self, directive):
        self.add_issue(
            severity=gixy.severity.LOW,
            directive=directive,
            reason="This regular expression, or one of its alternatives, is not anchored with `^` or `$`, "
            "so it can match anywhere in the input.",
        )
