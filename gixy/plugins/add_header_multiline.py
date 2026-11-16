import gixy
from gixy.directives.directive import MoreSetHeadersDirective
from gixy.plugins.plugin import Plugin


class add_header_multiline(Plugin):
    """
    Insecure example:
        add_header Content-Security-Policy "
        default-src: 'none';
        img-src data: https://mc.yandex.ru https://yastatic.net *.yandex.net
            https://mc.yandex.${tld} https://mc.yandex.ru;
        font-src data: https://yastatic.net;";
    """

    summary = "Multiline headers."
    severity = gixy.severity.LOW
    description = (
        "Header values must not contain line breaks (RFC 9110). NGINX sends them as they are, which breaks "
        "clients and upstreams."
    )
    help_url = "https://gixy.io/plugins/add_header_multiline/"
    directives = [
        "add_header",
        "add_trailer",
        "more_set_headers",
        "proxy_set_header",
        "grpc_set_header",
        "more_set_input_headers",
    ]

    def audit(self, directive):
        for header, value in _get_headers(directive).items():
            if value is None:
                continue
            if "\n\x20" in value or "\n\t" in value:
                reason = (
                    "Header value contains an obsolete folded newline (header folding)."
                )
                self.add_issue(directive=directive, reason=reason)
                break
            if "\n" in value:
                reason = "Header value contains a newline; the emitted header may be truncated or invalid."
                self.add_issue(directive=directive, reason=reason)
                break
            if "\r" in value:
                reason = "Header value contains a carriage return; the emitted header may be truncated or invalid."
                self.add_issue(directive=directive, reason=reason)
                break


def _get_headers(directive):
    if directive.name in ("add_header", "more_set_headers"):
        return directive.headers
    if directive.name == "more_set_input_headers":
        return MoreSetHeadersDirective.parse_headers(directive.args)
    if len(directive.args) >= 2:
        return {directive.args[0]: directive.args[1]}
    return {}
