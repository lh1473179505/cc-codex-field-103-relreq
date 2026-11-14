"""Minimal RFC 8941 subset for HTTP Message Signatures (RFC 9421).

Supported item types: token, string, integer, byte sequence, boolean.
Parameters and inner lists are supported. Dictionaries are used for
Signature, Signature-Input, and Content-Digest.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any


class SfvError(ValueError):
    pass


@dataclass
class Item:
    value: Any
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class InnerList:
    items: list[Item]
    params: dict[str, Any] = field(default_factory=dict)


Token = str  # tokens are stored as str with .__sfv_token__ via wrapper


class SfToken(str):
    pass


def _is_token(s: str) -> bool:
    return bool(re.fullmatch(r"[*a-zA-Z][a-zA-Z0-9!#$%&'*+\-.^_`|~]*", s))


def dumps_item(value: Any) -> str:
    if isinstance(value, Item):
        return dumps_item(value.value) + dumps_params(value.params)
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, SfToken):
        if not _is_token(value):
            raise SfvError(f"invalid token {value!r}")
        return str(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    if isinstance(value, str):
        # string
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return '"' + escaped + '"'
    raise SfvError(f"unsupported item {type(value)}")


def dumps_params(params: dict[str, Any]) -> str:
    parts = []
    for k, v in params.items():
        if not _is_token(k):
            raise SfvError(f"invalid param name {k!r}")
        if v is True:
            parts.append(f";{k}")
        else:
            parts.append(f";{k}={dumps_item(v)}")
    return "".join(parts)


def dumps_inner_list(lst: InnerList) -> str:
    pieces = []
    for it in lst.items:
        if isinstance(it, Item):
            pieces.append(dumps_item(it.value) + dumps_params(it.params))
        else:
            pieces.append(dumps_item(it))
    return "(" + " ".join(pieces) + ")" + dumps_params(lst.params)


def dumps_dict(d: dict[str, Any]) -> str:
    parts = []
    for k, v in d.items():
        if not _is_token(k):
            raise SfvError(f"invalid dict key {k!r}")
        if v is True:
            parts.append(k)
            continue
        if isinstance(v, InnerList):
            parts.append(f"{k}={dumps_inner_list(v)}")
        elif isinstance(v, Item):
            if v.value is True and not v.params:
                parts.append(k)
            else:
                parts.append(f"{k}={dumps_item(v.value)}{dumps_params(v.params)}")
        else:
            parts.append(f"{k}={dumps_item(v)}")
    return ", ".join(parts)


# ---- parser ----

class _P:
    def __init__(self, s: str):
        self.s = s
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def skip_ows(self) -> None:
        # "" in " \t" is True in Python; must test single characters only.
        while self.peek() in (" ", "\t"):
            self.i += 1

    def eat(self, ch: str) -> None:
        if self.peek() != ch:
            raise SfvError(f"expected {ch!r} at {self.i} in {self.s!r}")
        self.i += 1


def _parse_token(p: _P) -> SfToken:
    start = p.i
    if not re.match(r"[*a-zA-Z]", p.peek() or ""):
        raise SfvError(f"bad token at {p.i}")
    p.i += 1
    while re.match(r"[a-zA-Z0-9!#$%&'*+\-.^_`|~]", p.peek() or ""):
        p.i += 1
    return SfToken(p.s[start:p.i])


def _parse_string(p: _P) -> str:
    p.eat('"')
    out = []
    while not p.eof():
        c = p.peek()
        if c == '"':
            p.i += 1
            return "".join(out)
        if c == "\\":
            p.i += 1
            n = p.peek()
            if n not in '"\\':
                raise SfvError("bad escape")
            out.append(n)
            p.i += 1
            continue
        if ord(c) in (0x7F,) or (ord(c) < 0x20 and c not in ""):
            raise SfvError("bad char in string")
        out.append(c)
        p.i += 1
    raise SfvError("unterminated string")


def _parse_byteseq(p: _P) -> bytes:
    p.eat(":")
    start = p.i
    while p.peek() and p.peek() != ":":
        p.i += 1
    raw = p.s[start:p.i]
    p.eat(":")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as e:
        raise SfvError(f"bad byte sequence: {e}") from e


def _parse_number(p: _P) -> int:
    start = p.i
    if p.peek() == "-":
        p.i += 1
    if not p.peek().isdigit():
        raise SfvError("bad number")
    while p.peek().isdigit():
        p.i += 1
    if p.peek() == ".":
        raise SfvError("decimals are not in this subset")
    return int(p.s[start:p.i])


def _parse_bare_item(p: _P) -> Any:
    c = p.peek()
    if c == '"':
        return _parse_string(p)
    if c == ":":
        return _parse_byteseq(p)
    if c == "?":
        p.i += 1
        if p.peek() == "1":
            p.i += 1
            return True
        if p.peek() == "0":
            p.i += 1
            return False
        raise SfvError("bad boolean")
    if c == "-" or c.isdigit():
        return _parse_number(p)
    if c and re.match(r"[*a-zA-Z]", c):
        return _parse_token(p)
    raise SfvError(f"bad item at {p.i}: {p.s[p.i:p.i+20]!r}")


def _parse_params(p: _P) -> dict[str, Any]:
    params: dict[str, Any] = {}
    while p.peek() == ";":
        p.i += 1
        p.skip_ows()
        key = str(_parse_token(p))
        if p.peek() == "=":
            p.i += 1
            params[key] = _parse_bare_item(p)
        else:
            params[key] = True
    return params


def _parse_item(p: _P) -> Item:
    v = _parse_bare_item(p)
    params = _parse_params(p)
    return Item(v, params)


def _parse_inner_list(p: _P) -> InnerList:
    p.eat("(")
    p.skip_ows()
    items: list[Item] = []
    while p.peek() and p.peek() != ")":
        items.append(_parse_item(p))
        p.skip_ows()
    p.eat(")")
    params = _parse_params(p)
    return InnerList(items, params)


def parse_dict(s: str) -> dict[str, Item | InnerList]:
    p = _P(s.strip())
    out: dict[str, Item | InnerList] = {}
    p.skip_ows()
    if p.eof():
        return out
    while True:
        key = str(_parse_token(p))
        if p.peek() == "=":
            p.i += 1
            if p.peek() == "(":
                out[key] = _parse_inner_list(p)
            else:
                out[key] = _parse_item(p)
        else:
            params = _parse_params(p)
            out[key] = Item(True, params)
        p.skip_ows()
        if p.eof():
            break
        p.eat(",")
        p.skip_ows()
        if p.eof():
            raise SfvError("trailing comma")
    return out


def parse_item(s: str) -> Item:
    p = _P(s.strip())
    it = _parse_item(p)
    p.skip_ows()
    if not p.eof():
        raise SfvError("trailing junk")
    return it
