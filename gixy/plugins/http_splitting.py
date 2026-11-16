import gixy
from gixy.core.utils import basic_auth_enforced
from gixy.core.variable import compile_script
from gixy.directives.directive import REDIRECT_PREFIXES, MoreSetHeadersDirective
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
        for value in _get_values(directive):
            for var in compile_script(value):
                if directive.name == "rewrite" and _is_capture(var):
                    continue
                sources = list(_line_break_sources(var))
                if any(source.can_contain("\n") for source in sources):
                    char = "\\n"
                elif sources and not server_side:
                    char = "\\r"
                else:
                    continue
                if {source.name for source in sources} == {"remote_user"} and basic_auth_enforced(directive.parent):
                    continue
                reason = "Variable `${var}` can contain `{char}`, which can enable header/response splitting.".format(
                    var=var.name, char=char
                )
                self.add_issue(directive=[directive] + var.providers, reason=reason)


# Directives whose value goes into the request NGINX sends upstream.
SERVER_SIDE_DIRECTIVES = ("proxy_set_header", "proxy_pass", "more_set_input_headers")


def _is_capture(var):
    return isinstance(var.name, int)


def _line_break_sources(var, seen=None):
    """Leaf variables behind `var` that can carry CR or LF, without the captures `set` URL-escapes."""
    seen = set() if seen is None else seen
    if var in seen:
        return
    seen.add(var)
    children = var.alternatives or var.depends
    if not children and (var.can_contain("\n") or var.can_contain("\r")):
        yield var
    for child in children or ():
        if not _escaped_capture(var, child):
            yield from _line_break_sources(child, seen)


def _escaped_capture(var, dep):
    """True when `set` copies the numbered capture `dep` into `var` URL-escaped."""
    provider = var.provider
    if provider is None or provider.name != "set" or not _is_capture(dep):
        return False
    return _captured_from_uri(dep) and all(rewrite.stops_processing for rewrite in _preceding_rewrites(provider))


def _captured_from_uri(var):
    if var.alternatives:
        return all(_captured_from_uri(alternative) for alternative in var.alternatives)
    provider = var.provider
    if provider is None:
        return True
    if provider.name in ("location", "rewrite"):
        return True
    return provider.name == "if" and provider.variable in ("$uri", "$document_uri")


def _preceding_rewrites(directive):
    node = directive
    for parent in directive.parents:
        for child in parent.children:
            if child is node:
                break
            if child.name == "rewrite":
                yield child
            elif child.is_block and not child.self_context:
                yield from child.find("rewrite", flat=True)
        if parent.self_context:
            return
        node = parent


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
    elif directive.name in ("more_set_headers", "more_set_input_headers"):
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
    if directive.redirects:
        return directive.replace
    if "?" in directive.replace:
        return directive.replace.split("?", 1)[1]
    return None


def _get_error_page_location(directive):
    if len(directive.args) < 2:
        return None
    uri = directive.args[-1]
    if uri.startswith(REDIRECT_PREFIXES) or not uri.startswith(("/", "@", "$")):
        return uri
    return None
