import gixy
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

    def audit(self, directive):
        # This plugin performs checks in post_audit over full config
        return

    def post_audit(self, root):
        # Gather all server blocks recursively
        server_blocks = list(root.find_all_contexts_of_type("server"))
        if len(server_blocks) < 2:
            # Single server cannot be ambiguous
            return

        # Map listen socket -> list of (server_block, listen_directive, is_default)
        listen_groups = {}

        for srv in server_blocks:
            for listen in srv.find("listen"):
                key, is_default = self._parse_listen_key_and_default(listen.args)
                if not key:
                    # Could not parse a concrete socket
                    continue
                if key not in listen_groups:
                    listen_groups[key] = []
                listen_groups[key].append((srv, listen, is_default))

        # For each listen group with multiple servers and none marked default_server,
        # raise one issue per group (pointing to the first listen directive).
        for key, entries in listen_groups.items():
            if len(entries) < 2:
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

    def _parse_listen_key_and_default(self, args):
        """
        Parse a listen directive arguments list into a normalized socket key and
        whether it contains the default flag.

        Returns: (key, is_default) where key is a string like "*:80",
        "127.0.0.1:80", "[::]:443". If parsing fails, key is None.
        """
        is_default = any(a.lower() in ("default_server", "default") for a in args)

        address = None
        port = None

        for token in args:
            lower = token.lower()
            if lower in ("default_server", "default"):
                continue
            if lower.startswith("unix:"):
                # Not supported for ambiguity check
                return None, is_default
            if token.startswith("[") and "]" in token:
                # IPv6 like [::]:443 or [::1]:80
                addr_part = token
                address = addr_part.split("]")[0] + "]"
                if ":" in addr_part.split("]")[-1]:
                    # Something like "]:443"
                    try:
                        port = int(addr_part.split("]:")[-1])
                    except ValueError:
                        pass
                continue
            if ":" in token:
                # IPv4 or wildcard *:80
                host, p = token.split(":", 1)
                address = host if host else "*"
                try:
                    port = int(p)
                except ValueError:
                    pass
                continue
            if token.isdigit():
                port = int(token)
                # leave address as is (may be set by previous token),
                # otherwise assume wildcard
                continue
            # token could be bare address; leave parsing to a later numeric port token

        if port is None:
            return None, is_default
        if address is None or address == "0.0.0.0":
            address = "*"
        # Normalize IPv6 addresses to include brackets
        if ":" in address and not address.startswith("["):
            # It's likely an IPv6 without brackets (rare in nginx), keep as is
            pass
        key = f"{address}:{port}"
        return key, is_default
