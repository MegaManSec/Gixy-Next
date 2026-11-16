import ipaddress
import re
from collections import deque

AUTH_DIRECTIVES = ("auth_basic", "auth_request", "auth_jwt", "auth_oidc")

_BARE_VARIABLE_RE = re.compile(r"\$(?:([a-z_][a-z0-9_]*)|\{([a-z_][a-z0-9_]*)\})", re.IGNORECASE)


def is_indexed_name(name):
    return isinstance(name, int) or (len(name) == 1 and "1" <= name <= "9")


def resolve_inherited_single(scope, name):
    """Effective directive for an inheritable single-value directive.

    Walks from `scope` up to the root; the nearest scope that declares
    `name` wins, and within a scope the last declaration wins (nginx
    inheritance semantics). Returns the directive, or None when it is
    not set anywhere up the chain.
    """
    current = scope
    while current:
        matches = [
            c
            for c in current.children
            if (c.name or "").lower() == name and c.args
        ]
        if matches:
            return matches[-1]
        current = getattr(current, "parent", None)
    return None


def resolve_inherited_list(scope, name, inherit_name):
    """Directives of an inheritable list such as `add_header` in effect at `scope`.

    A scope that declares any replaces the inherited list, unless
    `<inherit_name> merge` applies, which appends it; `<inherit_name> off`
    stops inheritance (both nginx 1.29.3+).
    """
    result = []
    while scope is not None:
        own = scope.find(name)
        result += own
        mode = resolve_inherited_single(scope, inherit_name)
        mode = mode.arg(0).lower() if mode else "on"
        if mode == "off" or (own and mode != "merge"):
            break
        scope = scope.parent
    return result


def enforced_auth(scope):
    """Names of the authentication modules that restrict `scope`.

    A module is on when its nearest declaration is not exactly `off` (nginx
    compares case-sensitively). `auth_basic` restricts only with an
    `auth_basic_user_file` in effect; a file without an `http` block is
    assumed to get it from the main configuration.
    """
    enforced = set()
    for name in AUTH_DIRECTIVES:
        auth = resolve_inherited_single(scope, name)
        if auth is not None and auth.arg(0) != "off":
            enforced.add(name)
    if not _user_file_in_effect(scope):
        enforced.discard("auth_basic")
    return enforced


def _user_file_in_effect(scope):
    if resolve_inherited_single(scope, "auth_basic_user_file") is not None:
        return True
    return all(block.name != "http" for block in (scope, *scope.parents))


def satisfy_any(scope):
    """True when `satisfy any` is in effect for `scope`."""
    satisfy = resolve_inherited_single(scope, "satisfy")
    return satisfy is not None and satisfy.arg(0).lower() == "any"


def basic_auth_enforced(scope):
    """True when only users listed in the password file reach `scope`:
    `auth_basic` restricts it and `satisfy all` (the default) applies."""
    return "auth_basic" in enforced_auth(scope) and not satisfy_any(scope)


def parse_listen_key_and_default(args):
    """
    Parse a listen directive arguments list into a normalized socket key and
    whether it contains the default flag.

    Returns: (key, is_default) where key is a string like "*:80",
    "127.0.0.1:80", "[::]:443". If parsing fails, key is None.
    """
    if not args:
        return None, False

    params = [a.lower() for a in args[1:]]
    is_default = any(p in ("default_server", "default") for p in params)

    if args[0].lower().startswith("unix:"):
        # Not supported for ambiguity check
        return None, is_default

    address, port = split_address_port(args[0])
    if address is None:
        return None, is_default

    key = f"{address}:{port}"
    for datagram in ("udp", "quic"):
        if datagram in params:
            key = f"{key} {datagram}"
            break
    return key, is_default


def split_address_port(socket):
    """
    Split a listen socket argument into a normalized address and port.

    nginx accepts "address:port", a bare "address" (port 80 is implied) or
    a bare "port" (the wildcard address is implied).
    """
    if socket.startswith("["):
        address, _, port = socket.partition("]")
        address = normalize_address(address[1:])
        port = port[1:] if port.startswith(":") else port
    elif socket.isdigit():
        address, port = "*", socket
    elif socket.count(":") == 1:
        address, _, port = socket.partition(":")
        address = normalize_address(address)
    elif ":" in socket:
        return None, None
    else:
        address, port = normalize_address(socket), ""

    if not port:
        port = "80"
    if not port.isdigit():
        return None, None
    return address, int(port)


def normalize_address(address):
    """Collapse the spellings nginx treats as one listen address."""
    if address in ("", "*", "0.0.0.0"):
        return "*"
    if address.lower() == "localhost":
        return "127.0.0.1"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if parsed.version == 6:
        return f"[{parsed.compressed}]"
    return parsed.compressed


def bare_variable_name(value):
    """Name of the single variable a script consists of (`$var` or `${var}`),
    lowercased; None for literals, mixed scripts and empty values."""
    match = _BARE_VARIABLE_RE.fullmatch((value or "").strip().strip("\"'"))
    if not match:
        return None
    return (match.group(1) or match.group(2)).lower()


def resolve_variable_chain(name, assignments):
    """Assignments reachable from `$name` through bare-variable hops.

    `assignments(name)` yields (directive, value) pairs for the directives
    that may assign `$name`. Each pair is yielded with the hops walked to
    reach it, starting from the consumer's side, and a value that is itself
    a single variable is followed in turn. Every variable is expanded once,
    so cycles and diamonds terminate.
    """
    seen = {name}
    pending = deque([(name, ())])
    while pending:
        current, hops = pending.popleft()
        for directive, value in assignments(current):
            chain = hops + (directive,)
            yield chain, value
            following = bare_variable_name(value)
            if following and following not in seen:
                seen.add(following)
                pending.append((following, chain))


def default_listens(servers):
    """Map each server to the `listen` directives on whose socket it is the default server:
    the one flagged `default_server`, otherwise the first server on that socket."""
    sockets = {}
    defaults = {}
    for server in servers:
        listens = server.find("listen")
        if not listens:
            sockets.setdefault("*:80", []).append((server, None, False))
        for listen in listens:
            key, is_default = parse_listen_key_and_default(listen.args)
            if key is None:
                if is_default:
                    defaults.setdefault(server, []).append(listen)
                continue
            sockets.setdefault(key, []).append((server, listen, is_default))
    for entries in sockets.values():
        server, listen, _ = next((entry for entry in entries if entry[2]), entries[0])
        if listen is not None:
            defaults.setdefault(server, []).append(listen)
    return defaults
