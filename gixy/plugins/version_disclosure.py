import gixy
from gixy.plugins.plugin import Plugin


class version_disclosure(Plugin):
    """
    Syntax for the directive: server_tokens off;
    """

    summary = "NGINX version disclosure via server_tokens."
    severity = gixy.severity.LOW
    description = (
        "Using server_tokens on; or server_tokens build; allows an attacker to learn "
        "the NGINX version, which can be used to target known vulnerabilities."
    )
    help_url = "https://gixy.io/plugins/version_disclosure/"
    directives = ["server_tokens"]
    supports_full_config = True

    def audit(self, directive):
        if directive.args and directive.args[0].lower() in ["on", "build"]:
            self.add_issue(
                directive=directive,
                reason="`server_tokens` is set to a value that enables version disclosure.",
            )

    def post_audit(self, root):
        """Check for missing server_tokens directive in full config mode"""
        # Find http block
        http_block = None
        for child in root.children:
            if child.name == "http":
                http_block = child
                break

        if not http_block:
            return

        # Check if server_tokens is set at http level
        http_server_tokens = http_block.some("server_tokens")
        if http_server_tokens:
            return

        # Check each server block for server_tokens
        for server_block in http_block.find_all_contexts_of_type("server"):
            server_tokens = server_block.some("server_tokens")

            if not server_tokens:
                # Missing server_tokens directive in this server block
                self.add_issue(
                    directive=server_block,
                    reason="Missing `server_tokens`; default is `on`, which enables version disclosure.",
                )
