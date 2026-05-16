import fnmatch
import glob
import logging
import os
import re

from gixy.core.exceptions import InvalidConfiguration
from gixy.directives import block, directive
from gixy.parser import raw_parser
from gixy.parser.raw_parser import ParseException
from gixy.utils.text import to_native

LOG = logging.getLogger(__name__)


class NginxParser(object):
    def __init__(self, cwd="", allow_includes=True):
        self.cwd = cwd
        self.configs = {}
        self.is_dump = False
        self.allow_includes = allow_includes
        self.directives = {}
        self.parser = raw_parser.RawParser()
        self._init_directives()
        self._path_stack = None

    def parse_file(self, path, root=None, display_path=None):
        """Parse an nginx configuration file from disk.

        Args:
            path (str): Filesystem path to the nginx config to parse.
            root (Optional[block.Root]): Existing AST root to append into. If None, a new root is created.
            display_path (Optional[str]): Path to attribute to parsed nodes (used for stdin/tempfile attribution).

        Returns:
            block.Root: Parsed configuration tree.

        Raises:
            InvalidConfiguration: When parsing fails.
        """
        real_path = display_path if display_path else path
        LOG.debug("Parse file: {0}".format(real_path))
        root = self._ensure_root(root)
        try:
            parsed = self.parser.parse_path(path)
        except ParseException as e:
            # Preserve the underlying parser message and line info.
            base_msg = (
                getattr(e, "msg", None) or str(e) or "Failed to parse nginx config"
            )
            # Strip line number from error message (errors are not standardized)
            base_msg = re.sub(r":\d+$", "", base_msg)
            base_msg = re.sub(r":\d+$", "", base_msg)
            base_msg = re.sub(
                r"^(\s*)(\S)",
                lambda m: m.group(1) + m.group(2).upper(),
                base_msg,
                count=1,
            )

            # Add line number back to error message
            line = f" (line:{e.line})"
            error_msg = "{msg}{line}.".format(msg=base_msg, line=line)

            escaped_path = re.escape(path)
            ends_with_in_path_line = re.search(
                rf"in {escaped_path} \(line:\d+\)\.$", error_msg
            )
            if ends_with_in_path_line:
                error_msg = re.sub(
                    rf"in {escaped_path} \(line:(\d+)\)\.$",
                    rf"in {real_path} (line:\1).",
                    error_msg,
                )
            if not ends_with_in_path_line:
                error_msg = "{msg} in {filename}{line}.".format(
                    msg=base_msg, filename=real_path, line=line
                )

            LOG.error("{error}".format(error=error_msg))
            raise InvalidConfiguration(error_msg) from e

        current_path = display_path if display_path else path
        return self._build_tree_from_parsed(parsed, root, current_path)

    def parse_string(self, content, root=None, path_info=None):
        """Parse nginx configuration provided as a string/bytes.

        The content is written to a temporary file so that the underlying
        crossplane parser consistently receives a filesystem path (ensuring
        identical behavior to file-based parsing).

        Args:
            content (Union[str, bytes]): Nginx configuration text to parse.
            root (Optional[block.Root]): Existing AST root to append into. If None, a new root is created.
            path_info (Optional[str]): Path to attribute to parsed nodes (e.g., "<stdin>").

        Returns:
            block.Root: Parsed configuration tree.

        Raises:
            InvalidConfiguration: When parsing fails.
        """
        root = self._ensure_root(root)
        import tempfile

        data = (
            content
            if isinstance(content, (bytes, bytearray))
            else content.encode("utf-8")
        )
        tmp_filename = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".conf", delete=False
            ) as tmp:
                tmp.write(data)
                tmp_filename = tmp.name
            return self.parse_file(tmp_filename, root=root, display_path=path_info)
        except InvalidConfiguration:
            raise
        finally:
            if tmp_filename:
                try:
                    os.unlink(tmp_filename)
                except Exception:
                    pass

    # Backward-compatible alias (deprecated). Prefer parse_string.
    def parse(self, content, root=None, path_info=None):
        return self.parse_string(content, root=root, path_info=path_info)

    def _ensure_root(self, root):
        """Return provided root or create a new one.

        Args:
            root (Optional[block.Root]): Existing root node or None.

        Returns:
            block.Root: Root node.
        """
        return root if root else block.Root()

    def _build_tree_from_parsed(self, parsed_block, root, current_path):
        """Finalize parsed data into the directive tree.

        Handles nginx -T dumps, manages current file attribution, and
        appends parsed directives into the provided root.

        Args:
            parsed_block (list): Parsed representation from RawParser.
            root (block.Root): Root node to append into.
            current_path (str): Current file path used for attribution.

        Returns:
            block.Root: The root containing parsed directives.
        """
        # Handle nginx -T dump format if detected (multi-file with file delimiters)
        if (
            len(parsed_block)
            and isinstance(parsed_block[0], dict)
            and parsed_block[0].get("kind") == "file_delimiter"
        ):
            LOG.debug("Switched to parse nginx configuration dump.")
            root_filename = self._prepare_dump(parsed_block)
            self.is_dump = True
            self.cwd = os.path.dirname(root_filename)
            parsed_block = self.configs[root_filename]

        # Parse into the provided root/parent context and keep attribution
        old_stack = self._path_stack
        self._path_stack = current_path
        self.parse_block(parsed_block, root)
        self._path_stack = old_stack
        return root

    def parse_block(self, parsed_block, parent):
        for node in parsed_block:
            if not isinstance(node, dict):
                continue
            parsed_type = node.get("kind")
            if parsed_type == "comment" or parsed_type is None:
                continue

            if parsed_type == "include":
                # include is handled specially
                path_info = self.path_info
                try:
                    self._resolve_include(node["args"], parent)
                except (
                    InvalidConfiguration
                ):  # We can continue after error in parsed include file, I guess.
                    pass
                finally:
                    self._path_stack = path_info

                continue

            parsed_name = node.get("name")
            parsed_line = node.get("line")
            if parsed_type == "block":
                parsed_args = [node.get("args", []), node.get("children", [])]
            elif parsed_type == "directive":
                parsed_args = node.get("args", [])
            elif parsed_type == "hash_value":
                parsed_args = node.get("args", [])
            else:
                # unknown or file_delimiter should not be here
                continue

            if (
                parent.name in ["map", "geo"] and parsed_type == "directive"
            ):  # Hack because included maps are treated as directives (bleh)
                if isinstance(parsed_args, list) and len(parsed_args) > 1:
                    parent_args = getattr(parent, "args", []) or []
                    hdr = "{} {}".format(parent.name, " ".join(parent_args)).strip()
                    error_msg = (
                        "Invalid {} entry with {} parameters: {} {{ {} {}; }};".format(
                            parent.name,
                            len(parsed_args),
                            hdr,
                            parsed_name,
                            " ".join(parsed_args),
                        )
                    )
                    LOG.warn(
                        'Failed to parse "{path_info}": {error}'.format(
                            path_info=self.path_info, error=error_msg
                        )
                    )
                    continue
                parsed_type = "hash_value"

            directive_inst = self.directive_factory(
                parsed_type, parsed_name, parsed_args
            )
            if directive_inst:
                # RawParser emits 'raw' for *_lua_block
                if parsed_type == "block" and node.get("raw") is not None:
                    try:
                        setattr(directive_inst, "raw", node.get("raw"))
                    except Exception:
                        pass
                # Set line number and file path
                directive_inst.line = parsed_line
                directive_inst.file = self.path_info
                parent.append(directive_inst)

    def directive_factory(self, parsed_type, parsed_name, parsed_args):
        klass = self._get_directive_class(parsed_type, parsed_name)
        if not klass:
            return None

        if klass.is_block:
            args = [to_native(v).strip() for v in parsed_args[0]]
            children = parsed_args[1]

            inst = klass(parsed_name, args)
            self.parse_block(children, inst)
            return inst
        else:
            args = [to_native(v).strip() for v in parsed_args]
            return klass(parsed_name, args)

    def _get_directive_class(self, parsed_type, parsed_name):
        if (
            parsed_type in self.directives
            and parsed_name in self.directives[parsed_type]
        ):
            return self.directives[parsed_type][parsed_name]
        elif parsed_type == "block":
            return block.Block
        elif parsed_type == "directive":
            return directive.Directive
        elif parsed_type == "hash_value":
            return directive.MapDirective
        elif parsed_type == "unparsed_block":
            LOG.warning(
                "Skip unparseable block '%s' from '%s'", parsed_name, self.path_info
            )
            return None
        else:
            return None

    def _init_directives(self):
        self.directives["block"] = block.get_overrides()
        self.directives["directive"] = directive.get_overrides()

    def _resolve_include(self, args, parent):
        pattern = args[0]
        #  TODO(buglloc): maybe file providers?
        if self.is_dump:
            return self._resolve_dump_include(pattern=pattern, parent=parent)
        if not self.allow_includes:
            LOG.debug("Includes are disallowed, skip: {0}".format(pattern))
            return

        return self._resolve_file_include(pattern=pattern, parent=parent)

    def _resolve_file_include(self, pattern, parent):
        path = os.path.join(self.cwd, pattern)
        exists = False
        for file_path in sorted(glob.iglob(path)):
            exists = True
            # parse the include into current context
            self.parse_file(file_path, parent)

        if not exists:
            # Align behavior with nginx: unmatched glob patterns are not warnings
            if glob.has_magic(path):
                LOG.debug(
                    "Include pattern '%s' matched no files from '%s'",
                    path,
                    self.path_info,
                )
            else:
                LOG.warning("File not found: '%s'", path)

    def _resolve_dump_include(self, pattern, parent):
        path = os.path.join(self.cwd, pattern)
        found = False
        for file_path, parsed in self.configs.items():
            if not fnmatch.fnmatch(file_path, path):
                continue
            found = True

            # Flatten includes by parsing into the current parent context.
            # We only switch the path stack for correct file attribution but keep
            # cwd unchanged (prefix-based) so relative includes inside dumps
            # resolve as they commonly do in nginx deployments.
            # This intentionally diverges from commit 0ef30ce (which switches cwd
            # to the included file directory) to avoid mis-resolving patterns like
            # sites/default.conf including conf.d/listen -> /etc/nginx/conf.d/listen.
            old_stack = self._path_stack
            self._path_stack = file_path

            self.parse_block(parsed, parent)

            self._path_stack = old_stack

        if not found:
            # Align behavior with nginx: unmatched glob patterns are not warnings
            if glob.has_magic(path):
                LOG.debug("Include pattern matched no files: {0}".format(path))
            else:
                LOG.warning("File not found: {0}".format(path))

    def _prepare_dump(self, parsed_block):
        filename = ""
        root_filename = ""
        for node in parsed_block:
            if isinstance(node, dict) and node.get("kind") == "file_delimiter":
                if not filename:
                    root_filename = node.get("file")
                filename = node.get("file")
                self.configs[filename] = []
                continue
            self.configs[filename].append(node)
        return root_filename

    @property
    def path_info(self):
        """Current file being parsed, or None."""
        return self._path_stack if self._path_stack else None
