try:
    from cached_property import cached_property
except ImportError:
    from functools import cached_property

import ipaddress

import tldextract

from gixy.core.regexp import Regexp
from gixy.core.variable import Variable

_TLD = tldextract.TLDExtract(include_psl_private_domains=False, suffix_list_urls=())


def get_overrides():
    """Get a list of all directives that override the default behavior"""
    result = {}
    for klass in Directive.__subclasses__():
        if not klass.nginx_name:
            continue

        if not klass.__name__.endswith("Directive"):
            continue

        result[klass.nginx_name] = klass
    return result


def is_ipv6(host, strip_brackets=True, is_local=False):
    """Check if a string is an IPv6 address (may include port)."""
    if strip_brackets and host.startswith("[") and "]" in host:
        host = host.split("]", 1)[0][1:]
    try:
        ip_obj = ipaddress.IPv6Address(host)
        if is_local:
            return ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_private
        return True
    except ValueError:
        return False


def is_ipv4(host, strip_port=True, is_local=False):
    """Check if a string is an IPv4 address (may include port)."""
    if strip_port:
        host = host.rsplit(":", 1)[0]
    try:
        ip_obj = ipaddress.IPv4Address(host)
        if is_local:
            return ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local
        return True
    except ValueError:
        return False


class Directive:
    """Base class for all directives"""

    nginx_name = None
    is_block = False
    provide_variables = False

    def __init__(self, name, args, raw=None):
        self.name = name
        self.parent = None
        self.args = args
        self._raw = raw
        self.line = None  # Line number in source file
        self.file = None  # Source file path

    def set_parent(self, parent):
        """Set parent block for this directive"""
        self.parent = parent

    @property
    def parents(self):
        """Get all parent blocks"""
        parent = self.parent
        while parent:
            yield parent
            parent = parent.parent

    @property
    def variables(self):
        """Get all variables provided by this directive"""
        raise NotImplementedError()

    def _find_recursive_flat(self, node, name):
        """Find directives named `name` under `node` where self_context == False"""
        for child in getattr(node, "children", []):
            if child.name == name:
                yield child
            if getattr(child, "is_block", False):
                # Only flatten through non-self_context blocks (if/include/map/geo)
                if not getattr(child, "self_context", True):
                    yield from self._find_recursive_flat(child, name)
                # else: stop at real context boundary

    def find_declarative_directives_in_scope(self, name, ancestors=True):
        """Find declarative directives in the current scope, optionally from all ancestors too"""
        node = self
        parent = self.parent
        while parent:
            for child in parent.children:
                if child.name == name:
                    yield child

                if child.is_block and not child.self_context:
                    yield from self._find_recursive_flat(child, name)

                if child is node:
                    break

            if not ancestors:
                break

            node, parent = parent, parent.parent

    def find_imperative_directives_in_scope(self, name, ancestors=True):
        """Find imperative directives in the current scope, optionally from all ancestors too"""
        for parent in self.parents:
            yield from parent.find(name, flat=False)
            if not ancestors:
                break

    def find_single_directive_in_scope(self, name):
        """Find a single directive in the current scope"""
        for parent in self.parents:
            directive = parent.some(name, flat=False)
            if directive:
                return directive
        return None

    def __str__(self):
        return f"{self.name} {' '.join(self.args)};"


class AddHeaderDirective(Directive):
    """The add_header directive is used to add a header to the response"""

    nginx_name = "add_header"

    def __init__(self, name, args):
        super(AddHeaderDirective, self).__init__(name, args)
        self.header = args[0].lower()
        self.value = args[1]
        self.headers = {self.header: self.value}
        self.always = False
        if len(args) > 2 and args[2] == "always":
            self.always = True


class MoreSetHeadersDirective(Directive):
    """
    Syntax:	more_set_headers 'Foo: bar' 'Baz: bah';
    """

    nginx_name = "more_set_headers"

    def get_headers(self):
        result = {}
        skip_next = False
        for arg in self.args:
            if arg in ["-s", "-t"]:
                # Mark to skip the next value because it's not a header
                skip_next = True
            elif arg.startswith("-"):
                # Skip any options
                continue
            elif skip_next:
                skip_next = False
            elif not skip_next:
                # Now it's a header in format "Header: value" or "Header:" or just "Header" (for clearing)
                parts = arg.split(":", 1)
                header = parts[0]
                value = ""
                if len(parts) > 1 and parts[1].strip():
                    # strip only whitespace character from left side, preserving newlines
                    # this is needed to support multiline headers
                    value = parts[1].lstrip(" ")
                result[header] = value
        return result

    def __init__(self, name, args):
        super().__init__(name, args)
        self.headers = self.get_headers()
        # first header is the main header name
        self.header = list(self.headers.keys())[0]
        # value is
        self.value = self.headers[self.header]


class SetDirective(Directive):
    nginx_name = "set"
    provide_variables = True

    def __init__(self, name, args):
        super(SetDirective, self).__init__(name, args)
        self.variable = args[0].lstrip("$").lower()
        self.value = args[1]

    @property
    def variables(self):
        return [Variable(name=self.variable, value=self.value, provider=self)]


class AuthRequestSetDirective(Directive):
    nginx_name = "auth_request_set"
    provide_variables = True

    def __init__(self, name, args):
        super().__init__(name, args)
        self.variable = args[0].lstrip("$").lower()
        self.value = args[1]

    @property
    def variables(self):
        return [Variable(name=self.variable, value=self.value, provider=self)]


class PerlSetDirective(Directive):
    """The perl_set directive is used to set a value of a variable to a value"""

    nginx_name = "perl_set"
    provide_variables = True

    def __init__(self, name, args):
        super().__init__(name, args)
        self.variable = args[0].lstrip("$").lower()
        self.value = args[1]

    @property
    def variables(self):
        return [Variable(name=self.variable, provider=self, have_script=False)]


class SetByLuaDirective(Directive):
    nginx_name = "set_by_lua"
    provide_variables = True

    def __init__(self, name, args):
        super().__init__(name, args)
        self.variable = args[0].lstrip("$").lower()
        self.value = args[1]

    @property
    def variables(self):
        return [Variable(name=self.variable, provider=self, have_script=False)]


class RewriteDirective(Directive):
    nginx_name = "rewrite"
    provide_variables = True
    boundary = Regexp(r"[^\s\r\n]")

    def __init__(self, name, args):
        super().__init__(name, args)
        self.pattern = args[0]
        self.replace = args[1]
        self.flag = None
        if len(args) > 2:
            self.flag = args[2]

    @cached_property
    def _regexp(self):
        return Regexp(self.pattern, case_sensitive=True)

    @property
    def variables(self):
        regexp = self._regexp
        return [
            Variable(name=name, value=group, boundary=self.boundary, provider=self)
            for name, group in regexp.groups.items()
        ]


class RootDirective(Directive):
    """The root directive is used to define a directory that will hold the files."""

    nginx_name = "root"
    provide_variables = True

    def __init__(self, name, args):
        super().__init__(name, args)
        self.path = args[0]

    @property
    def variables(self):
        return [Variable(name="document_root", value=self.path, provider=self)]


class AliasDirective(Directive):
    nginx_name = "alias"

    def __init__(self, name, args):
        super().__init__(name, args)
        self.path = args[0]


class ResolverDirective(Directive):
    """
    Syntax:	resolver address ... [valid=time] [ipv4=on|off] [ipv6=on|off] [status_zone=zone];
    """

    nginx_name = "resolver"

    @cached_property
    def _external_nameservers(self):
        external_nameservers = []
        suffix_cache = {}
        for addr in self.addresses:
            ip_candidate = addr
            if addr.startswith("[") and "]" in addr:
                ip_candidate = addr.split("]", 1)[0][1:]  # [::1]:53 -> ::1
            elif addr.count(":") == 1:
                ip_candidate = addr.rsplit(":", 1)[
                    0
                ]  # 1.2.3.4:53 -> 1.2.3.4 (or name:53 -> name)

            if is_ipv4(addr, is_local=True) or is_ipv6(addr, is_local=True):
                continue

            try:
                ipaddress.ip_address(ip_candidate)  # is it even an ip address?
            except ValueError:
                host = ip_candidate.rstrip(".")  # example.com. -> example.com
                suffix = suffix_cache.get(host)
                if suffix is None:
                    suffix = _TLD(host).suffix
                    suffix_cache[host] = suffix
                if not suffix:
                    continue  # Non-registerable hostname
                external_nameservers.append(addr)
                continue

            external_nameservers.append(addr)
        return external_nameservers

    def __init__(self, name, args):
        super().__init__(name, args)
        addresses = []
        for arg in args:
            if "=" in arg:
                continue
            addresses.append(arg)
        self.addresses = addresses

    def get_external_nameservers(self):
        """Get a list of external nameservers used by the resolver directive"""
        return self._external_nameservers


class MapDirective(Directive):
    """
    map $source $destination {
        default value; <- this part
        key     value; <- this part
    }

    geo [$remote_addr] $destination {
      default        ZZ; <-- this part.
      include        conf/geo.conf; <-- this part.
      delete         127.0.0.0/16; <-- this part.
      proxy          192.168.100.0/24; <-- this part.
      proxy          2001:0db8::/32; <-- this part.
      key            value; <-- this part.
    }
    """

    nginx_name = "map"  # XXX: Also used for "geo". Could also work for "charset_map"
    provide_variables = True

    def __init__(self, source, destination):
        super().__init__(source, destination)
        self.src_val = source
        self.dest_val = (
            destination[0] if destination and len(destination) == 1 else None
        )
        self.regex = None

        if self.is_regex:
            if self.src_val.startswith("~*"):
                pattern = self.src_val[2:]
                cs = False
            else:
                pattern = self.src_val[1:]
                cs = True
            self.regex = Regexp(pattern, case_sensitive=cs)

    def __str__(self):
        map_str = self.src_val
        if self.dest_val:
            map_str += f" {self.dest_val}"
        map_str += ";"
        return map_str

    @property
    def is_regex(self):
        return self.src_val.startswith("~")

    @property
    def variables(self):
        if not self.regex:
            return []

        ancestor = self.parent
        while (
            ancestor is not None and ancestor.nginx_name != "map"
        ):  # XXX: Better to check isinstance(ancestor, MapBlock) but circular import..
            ancestor = getattr(ancestor, "parent", None)

        if (
            ancestor is None
        ):  # This happens for "geo" directives, which is ok because geo directive does not provide variables.
            return []

        result = []
        for name, group in self.regex.groups.items():
            result.append(
                Variable(
                    name=name,
                    value=group,
                    provider=self,
                    boundary=None,
                    ctx=self.src_val,
                )
            )
        return result
