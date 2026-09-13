import os
import traceback

import gixy
from gixy.core.diagnostics import Diagnostic
from gixy.core.exceptions import InvalidConfiguration, MalformedDirective
from gixy.directives.directive import MapDirective
from gixy.plugins.plugin import Plugin


class PluginsManager(object):
    def __init__(self, config=None):
        self.imported = False
        self.config = config
        self._plugins = []
        # Diagnostics for plugins that hit malformed input or failed
        # unexpectedly while auditing. Surfaced via Manager.errors / the CLI.
        self.audit_errors = []

    def import_plugins(self):
        if self.imported:
            return

        files_list = os.listdir(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins")
        )
        for plugin_file in files_list:
            if not plugin_file.endswith(".py") or plugin_file.startswith("_"):
                continue
            __import__(
                "gixy.plugins." + os.path.splitext(plugin_file)[0], None, None, [""]
            )

        self.imported = True

    def init_plugins(self):
        self.import_plugins()

        exclude = self.config.skips if self.config else None
        include = self.config.plugins if self.config else None
        severity = self.config.severity if self.config else None
        for plugin_cls in Plugin.__subclasses__():
            name = plugin_cls.__name__
            # Skip not needed plugins if include list is specified
            if include is not None:
                try:
                    if name not in include:
                        continue
                except TypeError:
                    # include doesn't support membership test, skip this check
                    pass
            # Skip plugins that are explicitly excluded
            if exclude is not None:
                try:
                    if name in exclude:
                        continue
                except TypeError:
                    # exclude doesn't support membership test, skip this check
                    pass
            if severity and not gixy.severity.is_acceptable(
                plugin_cls.severity, severity
            ):
                # Skip plugin by severity level
                continue
            if self.config and self.config.has_for(name):
                options = self.config.get_for(name)
            else:
                options = plugin_cls.options
            self._plugins.append(plugin_cls(options))

    @property
    def plugins(self):
        if not self._plugins:
            self.init_plugins()
        return self._plugins

    @property
    def plugins_classes(self):
        self.import_plugins()
        return Plugin.__subclasses__()

    def get_plugins_descriptions(self):
        return map(lambda a: a.name, self.plugins)

    def audit(self, directive):
        # A map/geo entry's name is its lookup key, not a directive name, so it
        # must not be dispatched to plugins that select by directive name: the
        # key is attacker-chosen text that can collide with any of them.
        is_hash_entry = isinstance(directive, MapDirective)
        for plugin in self.plugins:
            if plugin.directives and (
                is_hash_entry or directive.name not in plugin.directives
            ):
                continue
            self._run_plugin_safely(plugin, plugin.audit, directive, directive)

    def post_audit(self, root):
        """Call post_audit on plugins that support full config analysis when full config is detected."""
        if not self._is_full_config(root):
            return

        for plugin in self.plugins:
            if plugin.supports_full_config:
                self._run_plugin_safely(plugin, plugin.post_audit, root, None)

    def _run_plugin_safely(self, plugin, hook, arg, directive):
        """Run a plugin hook, isolating failures so one plugin can't abort the
        whole audit with an uncaught traceback.

        A MalformedDirective / InvalidConfiguration means the input is not valid
        nginx ("malformed"); any other exception is an unexpected failure — a
        likely Gixy-Next bug — recorded as "internal" with a traceback so it is
        reported rather than silently masked. Either way the audit continues.
        """
        try:
            hook(arg)
        except MalformedDirective as e:
            self._record("malformed", plugin, e.directive or directive, str(e))
        except InvalidConfiguration as e:
            self._record("malformed", plugin, directive, str(e))
        except Exception as e:
            self._record(
                "internal", plugin, directive,
                "{0}: {1}".format(type(e).__name__, e),
                tb=traceback.format_exc(),
            )

    def _record(self, kind, plugin, directive, message, tb=None):
        self.audit_errors.append(Diagnostic(
            kind, "audit", message,
            directive=getattr(directive, "name", None),
            line=getattr(directive, "line", None),
            file=getattr(directive, "file", None),
            plugin=plugin.name if plugin is not None else None,
            traceback=tb,
        ))

    def _is_full_config(self, root):
        """Detect if this is a full nginx config by checking for http block."""
        # Check if root has an http block child
        for child in root.children:
            if child.name == "http":
                return True
        return False

    def issues(self):
        result = []
        for plugin in self.plugins:
            if not plugin.issues:
                continue
            result.extend(plugin.issues)
        return result
