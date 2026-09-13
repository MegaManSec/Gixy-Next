"""This module provides a custom argument parser for Gixy."""

# flake8: noqa

import re
from collections import OrderedDict
from configargparse import *
from io import StringIO


import sys

from gixy.cli import EXIT_USAGE
from gixy.core.plugins_manager import PluginsManager

# used while parsing args to keep track of where they came from
_COMMAND_LINE_SOURCE_KEY = "command_line"
_ENV_VAR_SOURCE_KEY = "environment_variables"
_CONFIG_FILE_SOURCE_KEY = "config_file"
_DEFAULTS_SOURCE_KEY = "defaults"


class GixyConfigParser(DefaultConfigFileParser):
    def get_syntax_description(self):
        return ""

    def parse(self, stream):
        """Parses the keys + values from a config file."""

        def _unquote(s):
            s = s.strip()
            if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
                q = s[0]
                inner = s[1:-1]
                inner = inner.replace("\\\\", "\\").replace("\\" + q, q)
                return inner
            return s

        items = OrderedDict()
        prefix = ""

        # Precompile regex patterns for performance.
        white_space = r"\s*"
        key_pattern = r"(?P<key>[^:=;#\s]+?)"
        value_pattern = white_space + r"[:=]" + white_space + r"(?P<value>.*?)"
        comment_pattern = white_space + r"(?P<comment>\s[;#].*)?"
        regex_key_only = re.compile(r"^" + key_pattern + comment_pattern + r"$")
        regex_key_value = re.compile(
            r"^" + key_pattern + value_pattern + comment_pattern + r"$"
        )

        for i, line in enumerate(stream):
            line = line.strip()
            if not line or line[0] in ["#", ";"] or line.startswith("---"):
                continue
            if line[0] == "[":
                section = line[1:-1].strip()
                section_key = section.replace("_", "-")
                section_norm = section_key.lower()

                # Treat [gixy] as "global scope"
                if section_norm == "gixy":
                    prefix = ""
                else:
                    prefix = f"{section_key}-"

                continue

            key_only_match = regex_key_only.match(line)
            if key_only_match:
                key = key_only_match.group("key")
                items[prefix + key] = "true"
                continue

            key_value_match = regex_key_value.match(line)
            if key_value_match:
                key = key_value_match.group("key")
                value = key_value_match.group("value").strip()

                if value.startswith("[") and value.endswith("]"):
                    # handle a special case of lists
                    raw = value[1:-1].strip()
                    if raw:
                        elems = [e.strip() for e in raw.split(",")]
                        elems = [_unquote(e) for e in elems if e]
                        value = ",".join(elems)
                    else:
                        value = ""
                else:
                    value = _unquote(value)

                items[prefix + key] = value
                continue

            raise ConfigFileParserException(
                f"Unexpected line {i + 1} in {getattr(stream, 'name', 'stream')}: {line}"
            )
        return items

    def serialize(self, items):
        """Inverse of parsing: convert values back to config file contents."""
        r = StringIO()

        def fmt(v):
            # items values are (value, help)
            # but section values are OrderedDicts of key -> (value, help)
            if isinstance(v, bool):
                return "true" if v else "false"

            if isinstance(v, (list, tuple, set)):
                seq = list(v) if not isinstance(v, set) else sorted(v)
                return ",".join(str(x) for x in seq)

            if v is None:
                return ""

            return str(v)

        for key, value in items.items():
            if isinstance(value, OrderedDict):
                r.write(f"\n[{key}]\n")
                r.write(self.serialize(value))
            else:
                val, help = value
                if help:
                    r.write(f"; {help}\n")
                r.write(f"{key} = {fmt(val)}\n")

        return r.getvalue()


class GixyHelpFormatter(HelpFormatter):
    """Custom help formatter for Gixy."""

    def format_help(self):
        manager = PluginsManager()
        help_message = super(GixyHelpFormatter, self).format_help()
        if "plugins options:" in help_message:
            # Print available plugins _only_ if we print options for it
            plugins = "\n".join(
                "\t" + plugin.__name__
                for plugin in sorted(manager.plugins_classes, key=lambda p: p.__name__)
            )
            help_message = f"{help_message}\n\navailable plugins:\n{plugins}\n"
        return help_message


class ArgsParser(ArgumentParser):
    """Custom argument parser for Gixy."""

    def error(self, message):
        """Exit with the CLI's usage code rather than argparse's default 2,
        which the exit-code contract reserves for an unparsable nginx config."""
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, "{0}: error: {1}\n".format(self.prog, message))

    def get_possible_config_keys(self, action):
        """This method decides which actions can be set in a config file and
        what their keys will be. It returns a list of zero or more config keys that
        can be used to set the given action's value in a config file.
        """
        keys = []
        for arg in action.option_strings:
            if arg in ["--config", "--write-config", "--version"]:
                continue
            if any([arg.startswith(2 * c) for c in self.prefix_chars]):
                keys += [arg[2:], arg]  # eg. for '--bla' return ['bla', '--bla']

        return keys

    def get_items_for_config_file_output(self, source_to_settings, parsed_namespace):
        """
        Write an "effective config" file: for every action that can be set via
        config keys, write the final parsed value (after CLI/env/config/defaults).
        """
        config_file_items = OrderedDict()
        config_file_items["gixy"] = OrderedDict()

        for action in self._actions:
            config_file_keys = self.get_possible_config_keys(action)
            if not config_file_keys or action.is_positional_arg:
                continue

            # final value after parsing precedence
            value = getattr(parsed_namespace, action.dest, None)

            # If you want "full defaults", skip only None (keep False/0/empty lists)
            if value is None:
                continue

            # Normalize booleans to config-file friendly values
            if isinstance(value, bool):
                value = str(value).lower()

            # Put plugin options under [section]
            if ":" in action.dest:
                section, k = action.dest.split(":", 2)
                k = k.replace("_", "-")
                if section not in config_file_items:
                    config_file_items[section] = OrderedDict()
                config_file_items[section][k] = (value, action.help)
            else:
                # Use the primary key name (eg "debug", "level", "format")
                config_file_items["gixy"][config_file_keys[0]] = (
                    value,
                    action.help,
                )

        return config_file_items


def create_parser():
    """Create an argument parser for Gixy-Next."""
    return ArgsParser(
        description="Gixy-Next - The NGINX configuration analyzer\n\n",
        formatter_class=GixyHelpFormatter,
        config_file_parser_class=GixyConfigParser,
        auto_env_var_prefix="GIXY_",
        add_env_var_help=False,
        default_config_files=["/etc/gixy/gixy.cfg", "~/.config/gixy/gixy.conf"],
        args_for_setting_config_path=["-c", "--config"],
        args_for_writing_out_config_file=["--write-config"],
        add_config_file_help=False,
    )
