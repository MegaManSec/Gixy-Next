import gixy
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

    summary = "Multiline response headers."
    severity = gixy.severity.LOW
    description = (
        "Multiline headers are deprecated (see RFC 7230). Some clients never support "
        "them (for example, IE/Edge)."
    )
    help_url = "https://gixy.io/plugins/add_header_multiline/"
    directives = ["add_header", "more_set_headers"]

    def audit(self, directive):
        for header, value in directive.headers.items():
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
