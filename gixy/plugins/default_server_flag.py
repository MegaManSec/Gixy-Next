import gixy
from gixy.core.utils import enclosing_module, listen_sockets
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
        modules = {}
        for server in root.find_all_contexts_of_type("server"):
            module = enclosing_module(server)
            if module is not None and module.name not in self.MODULES_WITHOUT_DEFAULT_SERVER:
                modules.setdefault(module.name, []).append(server)
        for servers in modules.values():
            for key, entries in listen_sockets(servers).items():
                if len({server for server, _, _ in entries}) < 2 or any(is_default for _, _, is_default in entries):
                    continue
                self.add_issue(
                    directive=[listen or server for server, listen, _ in entries],
                    summary=self.summary,
                    description=(
                        f"No server marked as default_server for listen {key}. "
                        "Add 'default_server' to one server block listening on this socket."
                    ),
                    help_url=self.help_url,
                )
