from __future__ import absolute_import

import re

text_type = str
binary_type = (bytes, bytearray)

_CONTROL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def escape_control(text):
    """Render C0/C1 control characters and DEL, except tab and newline, as \\xNN."""
    return _CONTROL_RE.sub(lambda m: "\\x{0:02x}".format(ord(m.group())), text)


def to_bytes(obj, encoding="latin1", errors="strict", nonstring="replace"):
    if isinstance(obj, binary_type):
        return obj

    if isinstance(obj, text_type):
        try:
            # Try this first as it's the fastest
            return obj.encode(encoding, errors)
        except UnicodeEncodeError:
            return b"failed_to_encode"

    if nonstring == "simplerepr":
        try:
            value = str(obj)
        except UnicodeError:
            try:
                value = repr(obj)
            except UnicodeError:
                # Giving up
                return b"failed_to_encode"
    elif nonstring == "passthru":
        return obj
    elif nonstring == "replace":
        return b"failed_to_encode"
    elif nonstring == "strict":
        raise TypeError("obj must be a string type")
    else:
        raise TypeError(
            "Invalid value %s for to_bytes' nonstring parameter" % nonstring
        )

    return to_bytes(value, encoding, errors)


def to_text(obj, encoding="latin1", errors="strict", nonstring="replace"):
    if isinstance(obj, text_type):
        return obj

    if isinstance(obj, binary_type):
        try:
            return obj.decode(encoding, errors)
        except UnicodeEncodeError:
            return "failed_to_encode"

    if nonstring == "simplerepr":
        try:
            value = str(obj)
        except UnicodeError:
            try:
                value = repr(obj)
            except UnicodeError:
                # Giving up
                return "failed_to_encode"
    elif nonstring == "passthru":
        return obj
    elif nonstring == "replace":
        return "failed_to_encode"
    elif nonstring == "strict":
        raise TypeError("obj must be a string type")
    else:
        raise TypeError(
            "Invalid value %s for to_text's nonstring parameter" % nonstring
        )

    return to_text(value, encoding, errors)


to_native = to_text
