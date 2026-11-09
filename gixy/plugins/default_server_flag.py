import gixy
from gixy.core.utils import parse_listen_key_and_default
from gixy.plugins.plugin import Plugin


class default_server_flag(Plugin):
    """
    Warn when multiple server blocks share the same listen socket and none is
    explicitly marked as default_server (or default). Explicitly setting
    default_server removes ambiguity.
    """

    summary = "Multiple servers share listen socket without default_server."
    severity = gixy.severity.MEDIUM
    description = (
        "When two or more server blocks listen on the same address:port, one "
        "should be marked with the 'default_server' (or 'default') flag to "
        "avoid ambiguity about which server handles unmatched requests."
    )
    help_url = "https://gixy.io/plugins/default_server_flag/"
    directives = []
    supports_full_config = True

    # ngx_mail_core_module has no `default_server` listen parameter, and rejects
    # two servers on one socket outright instead of picking a default.
    MODULES_WITHOUT_DEFAULT_SERVER = ("mail",)

    def audit(self, directive):
        # This plugin performs checks in post_audit over full config
        return

    def post_audit(self, root):
        # Gather all server blocks recursively
        server_blocks = list(root.find_all_contexts_of_type("server"))
        if len(server_blocks) < 2:
            # Single server cannot be ambiguous
            return

        # Map (module, listen socket) -> list of (server_block, listen_directive, is_default)
        listen_groups = {}

        for srv in server_blocks:
            module = self._enclosing_module(srv)
            if module in self.MODULES_WITHOUT_DEFAULT_SERVER:
                continue
            listens = srv.find("listen")
            if not listens:
                # Only http gives a listen-less server an implicit socket
                if module != "http":
                    continue
                listen_groups.setdefault((module, "*:80"), []).append(
                    (srv, srv, False)
                )
                continue
            for listen in listens:
                key, is_default = parse_listen_key_and_default(listen.args)
                if not key:
                    # Could not parse a concrete socket
                    continue
                listen_groups.setdefault((module, key), []).append(
                    (srv, listen, is_default)
                )

        # For each listen group with multiple servers and none marked default_server,
        # raise one issue per group (pointing to the first listen directive).
        for (_, key), entries in listen_groups.items():
            if len({srv for (srv, _, _) in entries}) < 2:
                continue
            has_default = any(is_def for (_, _, is_def) in entries)
            if has_default:
                continue
            # Report once per ambiguous listen group
            listen_directives = [listen for (srv, listen, is_def) in entries]
            self.add_issue(
                directive=listen_directives,
                summary=self.summary,
                description=(
                    f"No server marked as default_server for listen {key}. "
                    "Add 'default_server' to one server block listening on this socket."
                ),
                help_url=self.help_url,
            )

    def _enclosing_module(self, server):
        """Return the module context ('http', 'stream', 'mail') holding a server block."""
        for parent in server.parents:
            if parent.name in ("http", "stream", "mail"):
                return parent.name
        return None
