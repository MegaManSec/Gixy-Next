try:
    from cached_property import cached_property
except ImportError:
    from functools import cached_property

from gixy.core.regexp import Regexp
from gixy.core.variable import Variable, compile_script
from gixy.directives.directive import Directive, MapDirective


def get_overrides():
    result = {}
    for klass in Block.__subclasses__():
        if not klass.nginx_name:
            continue

        if not klass.__name__.endswith("Block"):
            continue

        result[klass.nginx_name] = klass
    return result


class Block(Directive):
    nginx_name = None
    is_block = True
    self_context = True

    def __init__(self, name, args):
        super(Block, self).__init__(name, args)
        self.children = []
        self._children_by_name = {}

    def some(self, name, flat=True):
        """Find first directive with given name"""
        if not flat:
            lst = self._children_by_name.get(name)
            return lst[0] if lst else None

        for child in self.children:
            if child.name == name:
                return child
            if flat and child.is_block and not child.self_context:
                result = child.some(name, flat=flat)
                if result:
                    return result
        return None

    def find(self, name, flat=False):
        if not flat:
            return list(self._children_by_name.get(name, ()))

        result = []
        for child in self.children:
            if child.name == name:
                result.append(child)
            if child.is_block and not child.self_context:
                result.extend(child.find(name, flat=True))
        return result

    def find_recursive(self, name):
        result = []
        for child in self.children:
            if child.name == name:
                result.append(child)
            if child.is_block:
                result.extend(child.find_recursive(name))
        return result

    def append(self, directive):
        directive.set_parent(self)
        self.children.append(directive)
        self._children_by_name.setdefault(directive.name, []).append(directive)

    def find_children_directives(self, name):
        """Find directives below the current scope"""
        for child in self.children:
            if child.name == name:
                yield child
            if child.is_block:
                yield from child.find_children_directives(name)

    def find_all_contexts_of_type(self, context_type):
        """Find all block contexts of a specific type (e.g., 'server', 'location') in this scope"""
        for child in self.children:
            if child.is_block and child.name == context_type:
                yield child
            if child.is_block:
                yield from child.find_all_contexts_of_type(context_type)

    def __str__(self):
        return "{name} {args} {{".format(name=self.name, args=" ".join(self.args))


class Root(Block):
    nginx_name = None

    def __init__(self):
        super(Root, self).__init__(None, [])


class HttpBlock(Block):
    nginx_name = "http"

    def __init__(self, name, args):
        super(HttpBlock, self).__init__(name, args)


class ServerBlock(Block):
    nginx_name = "server"

    def __init__(self, name, args):
        super(ServerBlock, self).__init__(name, args)

    def get_names(self):
        return self.find("server_name")

    def __str__(self):
        server_names = [str(sn) for sn in self.find("server_name")]
        if server_names:
            return "server {{\n{0}\n".format("\n".join(server_names[:2]))
        return "server {"


class LocationBlock(Block):
    nginx_name = "location"
    provide_variables = True

    def __init__(self, name, args):
        super(LocationBlock, self).__init__(name, args)
        if len(args) == 2:
            self.modifier, self.path = args
        else:
            self.modifier = None
            self.path = args[0]

    @property
    def is_internal(self):
        return self.some("internal") is not None

    @property
    def is_regex(self):
        return self.modifier and self.modifier in ("~", "~*")

    @cached_property
    def _regexp(self):
        if not self.is_regex:
            return None
        return Regexp(self.path, case_sensitive=self.modifier == "~")

    @cached_property
    def variables(self):
        regexp = self._regexp
        if not regexp:
            return []
        return [
            Variable(name=name, value=group, boundary=None, provider=self)
            for name, group in regexp.groups.items()
        ]

    def needs_anchor(self):
        regexp = self._regexp
        if not regexp:
            return False
        return regexp.needs_tail_anchor()


class IfBlock(Block):
    nginx_name = "if"
    self_context = False

    def __init__(self, name, args):
        super(IfBlock, self).__init__(name, args)
        self.operand = None
        self.value = None
        self.variable = None

        if len(args) == 1:
            # if ($slow)
            self.variable = args[0].lower()  # Do not lstrip because this is not used for defining variables
        elif len(args) == 2:
            # if (!-e $foo)
            self.operand, self.value = args
        elif len(args) == 3:
            # if ($request_method = POST)
            self.variable = args[0].lower()
            self.operand = args[1]
            self.value = args[2]
        else:
            raise Exception('Unknown "if" definition, args: {0!r}'.format(args))

    @property
    def provide_variables(self):
        return self.operand in ("~", "~*", "!~", "!~*") and bool(self.value)

    def __str__(self):
        return "{name} ({args}) {{".format(name=self.name, args=" ".join(self.args))

    @property
    def is_regex(self):
        return self.operand and self.operand in ("~", "~*", "!~", "!~*")

    @cached_property
    def variables(self):
        if not self.is_regex or not self.value:
            return []

        boundary = None
        if self.variable:
            try:
                compiled_script = compile_script(self.variable)
                if len(compiled_script) == 1:
                    boundary = compiled_script[0].regexp
            except (IndexError, AttributeError):
                # compile_script may raise if the context of a variable cannot be found, such as in unit tests.
                pass

        regexp = Regexp(self.value, case_sensitive=self.operand in {"~", "!~"})
        result = []
        for name, group in regexp.groups.items():
            result.append(
                Variable(name=name, value=group, boundary=boundary, provider=self)
            )

        return result


class IncludeBlock(Block):
    nginx_name = "include"
    self_context = False

    def __init__(self, name, args):
        super(IncludeBlock, self).__init__(name, args)
        self.file_path = args[0]

    def __str__(self):
        return "include {0};".format(self.file_path)


class MapBlock(Block):
    """
    map $source $destination { <- this part is the block
        default value; <- this part is the directive, but MapBlock sets variables
        key     value; <- this part is the directive, but MapBlock sets variables
        ~*^re(.*)$ $1; <- this part is the directive, but MapBlock sets variables
    } <- this part is the block
    """

    nginx_name = "map"
    self_context = False
    provide_variables = True

    def __init__(self, name, args):
        super(MapBlock, self).__init__(name, args)
        self.source = args[0].lower()
        self.variable = args[1].lstrip("$").lower()

    def gather_map_directives(self, nodes):
        for node in nodes:
            if isinstance(node, MapDirective):
                yield node
            elif isinstance(node, IncludeBlock):
                yield from self.gather_map_directives(node.children)

    @cached_property
    def variables(self):
        vars = []
        for child in self.gather_map_directives(self.children):
            if not isinstance(child, MapDirective):
                continue  # XXX: Should never happen?
            src_val = child.src_val
            dest_val = child.dest_val

            if not child.is_regex:
                vars.append(
                    Variable(
                        name=src_val,
                        value=dest_val,
                        have_script=False,
                        provider=child,
                        ctx=src_val,
                    )
                )
                continue

            result = []
            for name, group in child.regex.groups.items():
                result.append(
                    Variable(
                        name=name,
                        value=group,
                        provider=child,
                        boundary=None,
                        ctx=src_val,
                    )
                )
                break  # Only need the first result (full expression)
            if len(result) != 1:
                continue
            vars.append(
                Variable(
                    name=src_val,
                    value=result[0].value,  # Value is Regexp()
                    boundary=None,
                    provider=child,
                    have_script=False,
                    ctx=src_val,
                ),
            )

        return [
            Variable(
                name=self.variable,
                value=vars,
                boundary=None,
                provider=self,
                have_script=False,
            )
        ]

    def __str__(self):
        return "{0} {1} {2} {{".format(self.nginx_name, self.args[0], self.args[1])


class GeoBlock(Block):
    """
    geo [$remote_addr] $geo { <- this part
      default        ZZ;
      include        conf/geo.conf;
      delete         127.0.0.0/16;
      proxy          192.168.100.0/24;
      proxy          2001:0db8::/32;
      key            value;
    } <- this part
    """

    nginx_name = "geo"
    self_context = False
    provide_variables = True

    def __init__(self, name, args):
        super(GeoBlock, self).__init__(name, args)
        if len(args) == 1:  # geo uses $remote_addr as default source of the value
            source = "$remote_addr"
            variable = args[0].lstrip("$").lower()
        else:
            source = args[0].lower()
            variable = args[1].lstrip("$").lower()
        self.source = source
        self.variable = variable

    def gather_geo_directives(self, nodes):
        for node in nodes:
            if isinstance(node, MapDirective):
                yield node
            elif isinstance(node, IncludeBlock):
                yield from self.gather_geo_directives(node.children)

    @cached_property
    def variables(self):
        vars = []
        for child in self.gather_geo_directives(self.children):
            src_val = child.src_val
            dest_val = child.dest_val

            vars.append(
                Variable(
                    name=src_val,
                    value=dest_val,
                    boundary=None,
                    provider=child,
                    have_script=False,
                    ctx=src_val,
                ),
            )
        return [
            Variable(
                name=self.variable,
                value=vars,
                boundary=None,
                provider=self,
                have_script=False,
            )
        ]

    def __str__(self):
        return "{0} {1} {{".format(self.nginx_name, " ".join(self.args))
