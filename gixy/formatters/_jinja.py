from __future__ import absolute_import

from jinja2 import Environment, PackageLoader

from gixy.utils.text import to_text


def load_template(name):
    env = Environment(
        loader=PackageLoader("gixy", "formatters/templates"),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    env.filters["to_text"] = to_text
    return env.get_template(name)
