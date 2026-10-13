"""Make model-written and log-written text safe to pass to Markdown-rendering widgets.

The model reads attacker-controlled logs, so anything it writes may carry Markdown
that would make the viewer's browser fetch a remote image or show a disguised link.
"""
from __future__ import annotations

import re

_ALL_MARKDOWN = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$:])")
_LINKS_AND_HTML = re.compile(r"([\[\]<])")


def plain(value) -> str:
    """Text shown literally: every Markdown control character is escaped."""
    if value is None:
        return ""
    return _ALL_MARKDOWN.sub(r"\\\1", str(value))


def report(value) -> str:
    """Markdown that keeps headings, lists and emphasis but cannot form links, images or HTML."""
    if value is None:
        return ""
    return _LINKS_AND_HTML.sub(r"\\\1", str(value))
