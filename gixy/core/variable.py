import logging
import re

from gixy.core.context import get_context
from gixy.core.regexp import Regexp

LOG = logging.getLogger(__name__)
# See ngx_http_script_compile in http/ngx_http_script.c
EXTRACT_RE = re.compile(r"\$([1-9]|[a-z_][a-z0-9_]*|\{[a-z0-9_]+\})", re.IGNORECASE)


def compile_script(script, ctx=None):
    """
    Compile Nginx script to list of variables.
    Example:
        compile_script('http://$foo:$bar') ->
            [Variable('http://'), Variable($foo), Variable(':', Variable($bar).

    :param str script: Nginx scrip.
    :return Variable[]: list of variable.
    """
    depends = []
    context = get_context()
    for i, var in enumerate(EXTRACT_RE.split(str(script))):
        if i % 2:
            # Variable
            var_val = var.strip("{}\x20").lower()
            var = context.get_var(var_val, ctx=ctx)
            if var:
                depends.append(var)
            else:
                LOG.info(
                    "Can't find variable '{0}' in script '{1}' inside block '{2}'.".format(
                        var_val, script, str(context.block).replace("\n", " ")
                    )
                )
        elif var:
            # Literal
            depends.append(Variable(name=None, value=var, have_script=False, ctx=ctx))
    return depends


class Variable(object):
    def __init__(
        self,
        name,
        value=None,
        boundary=None,
        provider=None,
        have_script=True,
        ctx=None,
    ):
        """
        Gixy Nginx variable class - parse and provide helpers to work with it.

        :param str|None name: variable name.
        :param str|Regexp value: variable value..
        :param Regexp boundary: variable boundary set.
        :param Directive provider: directive that provide variable (e.g. if, location, rewrite, etc.).
        :param bool have_script: may variable have nginx script or not (mostly used to indicate a string literal).
        :param str ctx: used for MapBlock/GeoBlock and MapDirective encapsulation
        """

        self.name = name
        self.value = value
        self.regexp = None
        self.depends = None
        self.boundary = boundary
        self.provider = provider
        self.final_value = value
        self.ctx = ctx
        if isinstance(value, Regexp):
            self.regexp = value
        elif have_script:
            self.depends = compile_script(
                value, ctx
            )  # XXX: Do we want to append new_depends below?
            for iteration in range(
                10
            ):  # 10 is arbitrary, just avoid infinite loop (is it possible?)
                new_depends = compile_script(self.final_value, ctx)
                if len(new_depends) == 0:
                    break
                if (
                    type(new_depends[0].value) is list
                ):  # MapBlock, GeoBlock cannot be infinitely resolved
                    self.final_value = self.value
                    break
                if len(new_depends) == 1 and self.final_value == new_depends[0].value:
                    break
                self.depends = new_depends
                all_vars = [str(i.value) for i in new_depends]
                self.final_value = "".join(all_vars)

    def can_contain(self, char):
        """
        Checks if variable can contain the specified char.

        :param str char: character to test.
        :return: True if variable can contain the specified char, False otherwise.
        """

        # First of all check boundary set
        if self.boundary and not self.boundary.can_contain(char):
            return False

        # Then regexp
        if self.regexp:
            return self.regexp.can_contain(char, skip_literal=True)

        # Then dependencies
        if self.depends:
            return any(dep.can_contain(char) for dep in self.depends)

        # If the value is a list (hash block), check all dest_val values
        if isinstance(self.value, list):
            for var in self.value:
                if (
                    not isinstance(var, Variable)
                    or not var.provider
                    or var.provider.nginx_name != "map"
                ):  # import MapDirective would be better but circular import..
                    continue  # break?
                if (
                    var.provider.parent.nginx_name != "map"
                ):  # import MapBlock would be better but circular import..
                    continue  # break?

                compiled_val = compile_script(
                    var.provider.dest_val, ctx=var.provider.src_val
                )  # Doesn't work for 'map $document_uri $v { ~*^[^\r\n]+$ $document_uri; }' but nothing we can do about that.
                for dep in compiled_val:
                    if dep.can_contain(char):
                        return True

        # Otherwise user can't control value of this variable
        return False

    def can_startswith(self, char):
        """
        Checks if variable can starts with the specified char.

        :param str char: character to test.
        :return: True if variable can starts with the specified char, False otherwise.
        """

        # First of all check boundary set
        if self.boundary and not self.boundary.can_startswith(char):
            return False

        # Then regexp
        if self.regexp:
            return self.regexp.can_startswith(char)

        # Then dependencies
        if self.depends:
            return self.depends[0].can_startswith(char)

        # If the value is a list (hash block), check all values
        if isinstance(self.value, list):
            for var in self.value:
                if (
                    not isinstance(var, Variable)
                    or not var.provider
                    or var.provider.nginx_name != "map"
                ):
                    continue
                if var.provider.parent.nginx_name != "map":
                    continue

                compiled_val = compile_script(
                    var.provider.dest_val, ctx=var.provider.src_val
                )
                if compiled_val:
                    if compiled_val[0].can_startswith(char):
                        return True

        # Otherwise user can't control value of this variable
        return False

    def must_contain(self, char):
        """
        Checks if variable MUST contain the specified char.

        :param str char: character to test.
        :return: True if variable must contain the specified char, False otherwise.
        """

        # First of all check boundary set
        if self.boundary and self.boundary.must_contain(char):
            return True

        # Then regexp
        if self.regexp:
            return self.regexp.must_contain(char)

        # Then dependencies
        if self.depends:
            return any(dep.must_contain(char) for dep in self.depends)

        # If the value is a list (hash block), check all values
        if isinstance(self.value, list):
            # Ensure that every map value must contain the char
            evaluated = False
            for var in self.value:
                if (
                    not isinstance(var, Variable)
                    or not var.provider
                    or var.provider.nginx_name != "map"
                ):
                    continue
                if var.provider.parent.nginx_name != "map":
                    continue

                compiled_val = compile_script(
                    var.provider.dest_val, ctx=var.provider.src_val
                )
                found_must_contain = False
                for dep in compiled_val:
                    if dep.must_contain(char):
                        found_must_contain = True
                        break
                if not found_must_contain:  # A map value doesn't need to contain the char, therefore return False
                    return False
                evaluated = True

            return evaluated

        # Otherwise checks literal
        return self.value and char in self.value

    def must_startswith(self, char):
        """
        Checks if variable MUST starts with the specified char.

        :param str char: character to test.
        :return: True if variable must starts with the specified char.
        """

        # First of all check boundary set
        if self.boundary and self.boundary.must_startswith(char):
            return True

        # Then regexp
        if self.regexp:
            return self.regexp.must_startswith(char)

        # Then dependencies
        if self.depends:
            return self.depends[0].must_startswith(char)

        # If the value is a list (hash block), check all values
        if isinstance(self.value, list):
            evaluated = False
            for var in self.value:
                if (
                    not isinstance(var, Variable)
                    or not var.provider
                    or var.provider.nginx_name != "map"
                ):
                    continue
                if var.provider.parent.nginx_name != "map":
                    continue

                compiled_val = compile_script(
                    var.provider.dest_val, ctx=var.provider.src_val
                )
                if not compiled_val or not compiled_val[0].must_startswith(char):
                    return False
                evaluated = True

            return evaluated

        # Otherwise checks literal
        return self.value and self.value[0] == char

    @property
    def providers(self):
        """
        Returns list of variable provides.

        :return Directive[]: providers.
        """
        result = []
        if self.provider:
            result.append(self.provider)
        if self.depends:
            for dep in self.depends:
                result += dep.providers
        return result
