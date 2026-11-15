import gixy
from gixy.core.utils import resolve_inherited_single
from gixy.core.variable import compile_script
from gixy.directives.directive import MoreSetHeadersDirective
from gixy.plugins.plugin import Plugin


class http_splitting(Plugin):
    r"""
    Insecure examples:
        rewrite ^ http://$host$uri;
        return 301 http://$host$uri;
        proxy_set_header "X-Original-Uri" $uri;
        proxy_pass http://upstream$document_uri;

        location ~ /proxy/(a|b)/(\W*)$ {
            proxy_pass http://storage/$2;
        }
    """

    summary = "Possible HTTP-Splitting vulnerability."
    severity = gixy.severity.HIGH
    description = (
        'Using variables that can contain "\\n" or "\\r" may lead to http injection.'
    )
    help_url = "https://gixy.io/plugins/http_splitting/"
    directives = [
        "rewrite",
        "return",
        "error_page",
        "add_header",
        "add_trailer",
        "more_set_headers",
        "proxy_set_header",
        "proxy_pass",
        "more_set_input_headers",
    ]

    def audit(self, directive):
        if any(parent.name == "stream" for parent in directive.parents):
            return
        server_side = directive.name in SERVER_SIDE_DIRECTIVES
        captures_escaped = directive.name == "rewrite"
        for value in _get_values(directive):
            for var in compile_script(value):
                if captures_escaped and _is_capture(var):
                    continue
                char = ""
                if _can_contain(var, "\n"):
                    char = "\\n"
                elif not server_side and _can_contain(var, "\r"):
                    char = "\\r"
                else:
                    continue
                if _line_break_sources(var) == {"remote_user"} and _basic_auth_enforced(directive):
                    continue
                reason = "Variable `${var}` can contain `{char}`, which can enable header/response splitting.".format(
                    var=var.name, char=char
                )
                self.add_issue(directive=[directive] + var.providers, reason=reason)


# Directives whose value goes into the request NGINX sends upstream.
SERVER_SIDE_DIRECTIVES = ("proxy_set_header", "proxy_pass", "more_set_input_headers")


def _is_capture(var):
    return isinstance(var.name, int)


def _escaped_capture(var, dep):
    """True when `set` copies the numbered capture `dep` into `var` URL-escaped."""
    provider = var.provider
    if provider is None or provider.name != "set" or not _is_capture(dep):
        return False
    return _captured_from_uri(dep) and not _rewrite_precedes(provider)


def _captured_from_uri(var):
    if var.alternatives:
        return all(_captured_from_uri(alternative) for alternative in var.alternatives)
    provider = var.provider
    if provider is None:
        return True
    if provider.name in ("location", "rewrite"):
        return True
    return provider.name == "if" and provider.variable in ("$uri", "$document_uri")


def _rewrite_precedes(directive):
    node = directive
    for parent in directive.parents:
        for child in parent.children:
            if child is node:
                break
            if child.name == "rewrite":
                return True
            if child.is_block and not child.self_context and child.find("rewrite", flat=True):
                return True
        if parent.self_context:
            return False
        node = parent
    return False


def _can_contain(var, char, seen=None):
    """Variable.can_contain, without the captures `set` URL-escapes."""
    seen = set() if seen is None else seen
    if id(var) in seen:
        return False
    seen.add(id(var))
    if var.boundary and not var.boundary.can_contain(char):
        return False
    if var.regexp or not (var.alternatives or var.depends):
        return var.can_contain(char)
    children = var.alternatives or [dep for dep in var.depends if not _escaped_capture(var, dep)]
    return any(_can_contain(child, char, seen) for child in children)


def _line_break_sources(var):
    """Names of the leaf variables behind `var` that can carry CR or LF."""
    names, seen = set(), set()

    def collect(current):
        if id(current) in seen:
            return
        seen.add(id(current))
        children = list(current.depends or ()) + list(current.alternatives or ())
        if not children:
            if current.name and (current.can_contain("\n") or current.can_contain("\r")):
                names.add(current.name)
            return
        for child in children:
            if not _escaped_capture(current, child):
                collect(child)

    collect(var)
    return names


def _basic_auth_enforced(directive):
    """True when ngx_http_auth_basic_module rejects every request whose user
    is not in the password file: realm and file set, and no `satisfy any`."""
    scope = directive.parent
    auth = resolve_inherited_single(scope, "auth_basic")
    if auth is None or auth.args[0].lower() == "off":
        return False
    if resolve_inherited_single(scope, "auth_basic_user_file") is None:
        return False
    satisfy = resolve_inherited_single(scope, "satisfy")
    return satisfy is None or satisfy.args[0].lower() == "all"


# nginx treats a lone `return` argument and a `rewrite` replacement as a redirect
# URL when it starts with one of these; the prefix check is case-sensitive
# (ngx_http_rewrite_return, ngx_http_rewrite).
REDIRECT_PREFIXES = ("http://", "https://", "$scheme")
# ngx_http_send_response() puts the value in Location for these statuses only;
# for every other status it is the response body.
REDIRECT_STATUSES = ("301", "302", "303", "307", "308")


def _get_values(directive):
    if directive.name == "proxy_pass" and len(directive.args) >= 1:
        values = [directive.args[0]]
    elif directive.name == "return":
        values = [_get_return_location(directive)]
    elif directive.name == "rewrite":
        values = [_get_rewrite_target(directive)]
    elif directive.name == "error_page":
        values = [_get_error_page_location(directive)]
    elif directive.name == "more_set_headers":
        values = list(directive.headers.values())
    elif directive.name == "more_set_input_headers":
        values = list(MoreSetHeadersDirective.parse_headers(directive.args).values())
    elif len(directive.args) >= 2:
        values = [directive.args[1]]
    else:
        values = []
    return [value for value in values if value]


def _get_return_location(directive):
    args = directive.args
    if len(args) == 1:
        return args[0] if args[0].startswith(REDIRECT_PREFIXES) else None
    if len(args) >= 2 and args[0] in REDIRECT_STATUSES:
        return args[1]
    return None


def _get_rewrite_target(directive):
    """The whole replacement of a redirect, the arguments of an internal rewrite."""
    if len(directive.args) < 2:
        return None
    replace = directive.args[1]
    flag = directive.args[2] if len(directive.args) > 2 else None
    if replace.startswith(REDIRECT_PREFIXES) or flag in ("redirect", "permanent"):
        return replace
    if "?" in replace:
        return replace.split("?", 1)[1]
    return None


def _get_error_page_location(directive):
    if len(directive.args) < 2:
        return None
    uri = directive.args[-1]
    if uri.startswith(REDIRECT_PREFIXES) or not uri.startswith(("/", "@", "$")):
        return uri
    return None
