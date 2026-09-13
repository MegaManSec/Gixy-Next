import copy
import logging

from gixy.core.utils import is_indexed_name

LOG = logging.getLogger(__name__)

CONTEXTS = []


def get_context():
    return CONTEXTS[-1]


def purge_context():
    del CONTEXTS[:]


def push_context(block):
    if len(CONTEXTS):
        context = copy.deepcopy(get_context())
    else:
        context = Context()
    context.set_block(block)
    CONTEXTS.append(context)
    return context


def pop_context():
    return CONTEXTS.pop()


class Context(object):
    def __init__(self):
        self.block = None
        self.variables = {"index": {}, "name": {}}

    def set_block(self, directive):
        self.block = directive
        return self

    def clear_index_vars(self):
        # Preserve context-scoped (tuple-keyed) indexed vars, e.g. map regex backrefs
        self.variables["index"] = {
            k: v for k, v in self.variables["index"].items() if isinstance(k, tuple)
        }
        return self

    def add_var(self, name, var):
        if is_indexed_name(name):
            var_type = "index"
            name = int(name)
        else:
            var_type = "name"

        key = (var.ctx, name) if var.ctx else name
        self.variables[var_type][key] = var
        return self

    def get_var(self, name, ctx=None):
        if is_indexed_name(name):
            var_type = "index"
            name = int(name)
        else:
            var_type = "name"

        key = (ctx, name) if ctx else name
        result = None
        try:
            result = self.variables[var_type][key]
        except KeyError:
            if var_type == "name":
                # Only named variables can be builtins
                import gixy.core.builtin_variables as builtins

                if builtins.is_builtin(name):
                    result = builtins.builtin_var(name)

        if not result:
            # We can try again if it's a MapDirective (ctx is set), because it may be
            # another variable in the same http context
            if ctx and var_type == "name":
                try:
                    result = self.variables[var_type][name]
                except KeyError:
                    # It may actually be another variable outside of the same http
                    # context, but we have no way to traverse up and down all contexts.
                    # So, just create a fake variable with the same name, and the caller
                    # can use compile_script during a second pass if it wants to resolve
                    # the variable.
                    import gixy.core.builtin_variables as builtins

                    result = builtins.fake_var(name)

        return result

    def __deepcopy__(self, memo):
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        result.block = copy.copy(self.block)
        result.variables = {
            "index": copy.copy(self.variables["index"]),
            "name": copy.copy(self.variables["name"]),
        }
        return result
