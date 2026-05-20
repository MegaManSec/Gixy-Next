import logging
import os

import gixy
from gixy.core import builtin_variables as builtins
from gixy.core.config import Config
from gixy.core.context import get_context, pop_context, purge_context, push_context
from gixy.core.plugins_manager import PluginsManager
from gixy.directives.block import GeoBlock, MapBlock
from gixy.directives.directive import (
    AuthRequestSetDirective,
    MapDirective,
    PerlSetDirective,
    RewriteDirective,
    RootDirective,
    SetByLuaDirective,
    SetDirective,
)
from gixy.core.regexp import Regexp
from gixy.parser.nginx_parser import NginxParser

# Directives that register a named variable visible throughout their enclosing
# scope regardless of source order, matching nginx's parse-time registration.
SCOPE_STATIC_VAR_PROVIDERS = (
    SetDirective,
    AuthRequestSetDirective,
    PerlSetDirective,
    SetByLuaDirective,
    MapBlock,
    GeoBlock,
)

LOG = logging.getLogger(__name__)


class Manager(object):
    def __init__(self, config=None):
        self.root = None
        self.config = config or Config()
        self.auditor = PluginsManager(config=self.config)

    def audit(self, file_path, file_data, is_stdin=False):
        LOG.debug("Audit config file: {fname}".format(fname=file_path))
        # Load custom variables if configured
        try:
            vars_dirs = getattr(self.config, "vars_dirs", None)
            if vars_dirs:
                builtins.load_custom_variables_from_dirs(vars_dirs)
        except Exception as e:
            LOG.debug("Custom variables loading failed: %s", e)
        parser = NginxParser(
            cwd=os.path.dirname(file_path) if not is_stdin else "",
            allow_includes=self.config.allow_includes,
        )
        if is_stdin:
            # Route stdin through parse_string for consistent path-based parsing via tempfile
            self.root = parser.parse_string(
                content=file_data.read(), path_info=file_path
            )
        else:
            # Prefer path-based parsing to avoid temporary files
            self.root = parser.parse_file(file_path)

        push_context(self.root)
        self._audit_recursive(self.root.children)
        # Call post_audit hooks after all directives have been processed
        self.auditor.post_audit(self.root)

    @property
    def results(self):
        for plugin in self.auditor.plugins:
            if plugin.issues:
                yield plugin

    @property
    def stats(self):
        stats = dict.fromkeys(gixy.severity.ALL, 0)
        for plugin in self.auditor.plugins:
            base_severity = plugin.severity
            for issue in plugin.issues:
                # TODO(buglloc): encapsulate into Issue class?
                severity = issue.severity if issue.severity else base_severity
                stats[severity] += 1
        return stats

    def _audit_recursive(self, tree):
        self._prepopulate_scope_var_names(tree)
        self._prepopulate_scope_var_values(tree)
        for directive in tree:
            self._update_variables(directive)
            self.auditor.audit(directive)
            if directive.is_block:
                if directive.self_context:
                    push_context(directive)
                self._audit_recursive(directive.children)
                if directive.self_context:
                    pop_context()

    def _prepopulate_scope_var_names(self, tree):
        context = get_context()
        for directive in tree:
            if isinstance(directive, SCOPE_STATIC_VAR_PROVIDERS):
                name = directive.variable
                if name not in context.variables["name"]:
                    context.add_var(name, builtins.fake_var(name))
            elif isinstance(directive, RootDirective):
                if "document_root" not in context.variables["name"]:
                    context.add_var("document_root", builtins.fake_var("document_root"))
            elif isinstance(directive, RewriteDirective):
                # Rewrite captures persist in script-engine state and are
                # referenceable by subsequent directives in this scope
                # regardless of source order.
                self._register_regex_captures(directive.pattern)
            elif directive.is_block and not directive.self_context:
                if directive.provide_variables:
                    value = getattr(directive, 'value', None)
                    if value:
                        self._register_regex_captures(value)
                self._prepopulate_scope_var_names(directive.children)

    def _register_regex_captures(self, pattern):
        """Add fake vars for every named/numeric capture in `pattern` to the
        current scope, so forward references compile cleanly during the names
        pass."""
        context = get_context()
        try:
            for name in Regexp(pattern).groups.keys():
                if isinstance(name, str):
                    if name not in context.variables["name"]:
                        context.add_var(name, builtins.fake_var(name))
                elif name != 0 and name not in context.variables["index"]:
                    context.add_var(name, builtins.fake_var(str(name)))
        except Exception:
            pass

    def _prepopulate_scope_var_values(self, tree):
        context = get_context()
        for directive in tree:
            if isinstance(directive, SCOPE_STATIC_VAR_PROVIDERS + (RootDirective, RewriteDirective)):
                for var in directive.variables:
                    context.add_var(var.name, var)
            elif directive.is_block and not directive.self_context:
                if directive.provide_variables:
                    for var in directive.variables:
                        context.add_var(var.name, var)
                self._prepopulate_scope_var_values(directive.children)

    def _update_variables(self, directive):
        # TODO(buglloc): finish him!
        if not directive.provide_variables:
            return

        context = get_context()
        for var in directive.variables:
            if var.name == 0 and not isinstance(directive, MapDirective):
                # All regexps must clean indexed variables
                context.clear_index_vars()
            context.add_var(var.name, var)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        purge_context()
