"""Fail-closed parser for the canonical workflow YAML used in security tests.

This module is intentionally not a general-purpose YAML implementation.  It
accepts only the small, reviewable subset emitted by the two controller
workflows: two-space mappings and sequences, JSON-style double-quoted strings,
plain scalar leaves, empty mappings, and literal blocks.  Any unsupported YAML
feature is rejected so a valid-but-unreviewed construct cannot evade the frozen
workflow contracts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_KEY_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_INTEGER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_UNSUPPORTED_SCALAR_PREFIXES = ("&", "*", "!", "[", "{", "|", ">", "'")


class RestrictedYamlError(ValueError):
    """Raised when a document leaves the deliberately small YAML subset."""


@dataclass(frozen=True)
class _Token:
    """One significant canonical-YAML line."""

    indent: int
    text: str
    line_number: int
    literal: str | None = None


def parse_restricted_workflow(document: str) -> dict[str, Any]:
    """Parse one workflow and reject every unsupported YAML construct."""

    tokens = _tokenize(document)
    if not tokens:
        raise RestrictedYamlError("workflow is empty")
    parsed, next_index = _parse_node(tokens, 0, 0)
    if next_index != len(tokens) or not isinstance(parsed, dict):
        raise RestrictedYamlError("workflow did not parse as one mapping")
    return parsed


def _tokenize(document: str) -> list[_Token]:
    """Convert significant lines and literal bodies into immutable tokens."""

    raw_lines = document.splitlines()
    tokens: list[_Token] = []
    index = 0
    while index < len(raw_lines):
        raw = raw_lines[index]
        line_number = index + 1
        _reject_tabs(raw, line_number)
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if indent % 2:
            raise RestrictedYamlError(f"indent must be even at line {line_number}")
        text = _strip_inline_comment(stripped)
        if text.endswith(": |"):
            literal, index = _read_literal(raw_lines, index, indent)
            tokens.append(
                _Token(
                    indent=indent,
                    text=text[:-2].rstrip(),
                    line_number=line_number,
                    literal=literal,
                )
            )
            continue
        tokens.append(_Token(indent=indent, text=text, line_number=line_number))
        index += 1
    return tokens


def _read_literal(
    raw_lines: list[str],
    parent_index: int,
    parent_indent: int,
) -> tuple[str, int]:
    """Read a canonical literal block indented exactly below its key."""

    lines: list[str] = []
    index = parent_index + 1
    while index < len(raw_lines):
        raw = raw_lines[index]
        line_number = index + 1
        _reject_tabs(raw, line_number)
        if raw.strip():
            child_indent = len(raw) - len(raw.lstrip(" "))
            if child_indent <= parent_indent:
                break
            if child_indent < parent_indent + 2:
                raise RestrictedYamlError(
                    f"invalid literal indentation at line {line_number}"
                )
            lines.append(raw[parent_indent + 2 :])
        else:
            lines.append("")
        index += 1
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines), index


def _reject_tabs(line: str, line_number: int) -> None:
    if "\t" in line:
        raise RestrictedYamlError(f"tabs are forbidden at line {line_number}")


def _strip_inline_comment(value: str) -> str:
    """Strip an inline comment while preserving hashes inside JSON strings."""

    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote == '"':
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    if quote is not None:
        raise RestrictedYamlError("unterminated quoted scalar")
    return value.rstrip()


def _parse_node(
    tokens: list[_Token],
    index: int,
    indent: int,
) -> tuple[Any, int]:
    if index >= len(tokens) or tokens[index].indent != indent:
        raise RestrictedYamlError("missing canonical YAML node")
    if tokens[index].text.startswith("- "):
        return _parse_sequence(tokens, index, indent)
    return _parse_mapping(tokens, index, indent)


def _parse_mapping(
    tokens: list[_Token],
    index: int,
    indent: int,
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(tokens):
        token = tokens[index]
        if token.indent < indent:
            break
        if token.indent > indent:
            raise RestrictedYamlError(
                f"unexpected indentation at line {token.line_number}"
            )
        if token.text.startswith("- "):
            break
        key, raw_value = _mapping_entry(token)
        if key in result:
            raise RestrictedYamlError(
                f"duplicate key {key!r} at line {token.line_number}"
            )
        index += 1
        if token.literal is not None:
            if raw_value:
                raise RestrictedYamlError(
                    f"literal block has inline value at line {token.line_number}"
                )
            result[key] = token.literal
        elif raw_value:
            result[key] = _parse_scalar(raw_value)
        elif index < len(tokens) and tokens[index].indent > indent:
            _require_child_indent(tokens[index], indent)
            result[key], index = _parse_node(tokens, index, indent + 2)
        else:
            result[key] = None
    return result, index


def _parse_sequence(
    tokens: list[_Token],
    index: int,
    indent: int,
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(tokens):
        token = tokens[index]
        if token.indent < indent:
            break
        if token.indent != indent or not token.text.startswith("- "):
            raise RestrictedYamlError(
                f"canonical sequence item expected at line {token.line_number}"
            )
        remainder = token.text[2:].strip()
        index += 1
        match = re.fullmatch(r"([A-Za-z0-9_-]+):(.*)", remainder)
        if match is None:
            if token.literal is not None or not remainder:
                raise RestrictedYamlError(
                    f"non-canonical sequence item at line {token.line_number}"
                )
            result.append(_parse_scalar(remainder))
            continue

        key, raw_value = match.groups()
        item: dict[str, Any] = {
            key: _parse_scalar(raw_value.strip()) if raw_value.strip() else None
        }
        if index < len(tokens) and tokens[index].indent > indent:
            _require_child_indent(tokens[index], indent)
            continuation, index = _parse_mapping(tokens, index, indent + 2)
            duplicate_keys = item.keys() & continuation.keys()
            if duplicate_keys:
                duplicate = sorted(duplicate_keys)[0]
                raise RestrictedYamlError(f"duplicate item key {duplicate!r}")
            item.update(continuation)
        result.append(item)
    return result, index


def _mapping_entry(token: _Token) -> tuple[str, str]:
    if ":" not in token.text:
        raise RestrictedYamlError(f"mapping entry expected at line {token.line_number}")
    key, raw_value = token.text.split(":", 1)
    if _KEY_RE.fullmatch(key) is None:
        raise RestrictedYamlError(
            f"non-canonical key {key!r} at line {token.line_number}"
        )
    return key, raw_value.strip()


def _require_child_indent(token: _Token, parent_indent: int) -> None:
    if token.indent != parent_indent + 2:
        raise RestrictedYamlError(
            f"unexpected child indentation at line {token.line_number}"
        )


def _parse_scalar(value: str) -> Any:
    if value == "{}":
        return {}
    if value == "true":
        return True
    if value == "false":
        return False
    if value.startswith('"'):
        parsed = json.loads(value)
        if not isinstance(parsed, str):
            raise RestrictedYamlError("only quoted strings are accepted")
        return parsed
    if _INTEGER_RE.fullmatch(value):
        return int(value)
    if value.startswith(_UNSUPPORTED_SCALAR_PREFIXES):
        raise RestrictedYamlError(f"unsupported scalar syntax: {value!r}")
    if " &" in value or " *" in value or " <<" in value:
        raise RestrictedYamlError(f"unsupported YAML feature: {value!r}")
    return value
