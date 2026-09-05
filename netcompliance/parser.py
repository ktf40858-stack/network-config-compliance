"""Parse a Cisco IOS running-configuration into an indentation-based tree.

IOS configuration is hierarchical but the hierarchy is only expressed by leading
whitespace, so a flat regex over the text cannot tell an ``ip address`` inside an
interface block from one inside a VRF definition. Everything else in this package
depends on getting that distinction right.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class ConfigLine:
    """One configuration line and the block nested underneath it."""

    text: str
    indent: int
    lineno: int
    children: list["ConfigLine"] = field(default_factory=list)
    parent: "ConfigLine | None" = None

    def __str__(self) -> str:
        return self.text

    def walk(self) -> Iterator["ConfigLine"]:
        """Yield this line and every descendant, depth first."""
        yield self
        for child in self.children:
            yield from child.walk()

    def find_children(self, pattern: str) -> list["ConfigLine"]:
        """Direct children whose text matches ``pattern``."""
        rx = re.compile(pattern)
        return [c for c in self.children if rx.search(c.text)]

    @property
    def path(self) -> str:
        """Readable position, e.g. ``interface GigabitEthernet0/1 > ip address ...``."""
        if self.parent is None or self.parent.text == "<root>":
            return self.text
        return f"{self.parent.path} > {self.text}"


class IOSConfig:
    """A parsed running-configuration."""

    #: Lines that carry no configuration meaning.
    _IGNORED = re.compile(r"^\s*(!|#|Building configuration|Current configuration)")

    def __init__(self, text: str, source: str = "<string>") -> None:
        self.source = source
        self.raw = text
        self.root = ConfigLine(text="<root>", indent=-1, lineno=0)
        self._parse(text)

    @classmethod
    def from_file(cls, path: str) -> "IOSConfig":
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return cls(handle.read(), source=path)

    def _parse(self, text: str) -> None:
        stack: list[ConfigLine] = [self.root]

        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            if not raw_line.strip() or self._IGNORED.match(raw_line):
                continue

            indent = len(raw_line) - len(raw_line.lstrip())
            line = ConfigLine(text=raw_line.strip(), indent=indent, lineno=lineno)

            # Unwind to the first ancestor that is less indented than this line.
            while len(stack) > 1 and stack[-1].indent >= indent:
                stack.pop()

            line.parent = stack[-1]
            stack[-1].children.append(line)
            stack.append(line)

    # -- querying -----------------------------------------------------------

    @property
    def lines(self) -> list[ConfigLine]:
        """Every line in the configuration, flattened."""
        return [line for line in self.root.walk() if line is not self.root]

    @property
    def global_lines(self) -> list[ConfigLine]:
        """Top-level lines only."""
        return list(self.root.children)

    def find(self, pattern: str) -> list[ConfigLine]:
        """Every line anywhere in the configuration matching ``pattern``."""
        rx = re.compile(pattern)
        return [line for line in self.lines if rx.search(line.text)]

    def find_global(self, pattern: str) -> list[ConfigLine]:
        """Top-level lines matching ``pattern``."""
        rx = re.compile(pattern)
        return [line for line in self.global_lines if rx.search(line.text)]

    def blocks(self, pattern: str) -> list[ConfigLine]:
        """Top-level blocks whose header matches ``pattern`` (interfaces, line vty, ...)."""
        return self.find_global(pattern)

    @property
    def hostname(self) -> str:
        match = self.find_global(r"^hostname\s+(\S+)")
        if match:
            return match[0].text.split()[1]
        return "unknown"
