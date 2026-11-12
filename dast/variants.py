"""Deterministic payload mutation variants.

Every payload is exercised with exactly five distinct variants:
``original``, ``url_encoded``, ``double_url_encoded``, ``case_swapped`` and
``homoglyph``.  Mutations that would otherwise produce a no-op get an explicit
Unicode fallback so that two variants of the same payload can never be sent to
an endpoint twice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List
from urllib.parse import quote, unquote


VARIANT_NAMES = (
    "original",
    "url_encoded",
    "double_url_encoded",
    "case_swapped",
    "homoglyph",
)


# Cyrillic look-alikes (confusables), plus visually similar full-width glyphs
# used when a payload contains no Latin letter that can be replaced.
HOMOGLYPH_MAP: Dict[str, str] = {
    "a": "\u0430",  # Cyrillic a
    "A": "\u0410",
    "e": "\u0435",  # Cyrillie ie
    "E": "\u0415",
    "o": "\u043e",  # Cyrillic o
    "O": "\u041e",
    "p": "\u0440",  # Cyrillic er
    "P": "\u0420",
    "c": "\u0441",  # Cyrillic es
    "C": "\u0421",
    "x": "\u0445",  # Cyrillic ha
    "X": "\u0425",
    "s": "\u0555",  # Armenian vo (looks like s)
    "S": "\u0555",
    "i": "\u0456",  # Cyrillic i
    "I": "\u0406",
    "t": "\u0482",  # Cyrillic semisoft sign, tall t-like glyph
    "T": "\u0422",  # Cyrillic te
    "r": "\u0280",  # Latin small capital r
    "R": "\u042f",  # Cyrillic ya (rough R shape)
    "n": "\u0578",  # Armenian vo smaller n-like glyph
    "N": "\u0504",
    "l": "\u04CF",  # Cyrillic el with tail
    "L": "\u0428",
    "u": "\u057D",  # Armenian yi
    "U": "\u054D",
    "d": "\u0501",
    "D": "\u0405",
}

# Fallback replacements for non-letter symbols/digits used by template and
# punctuation-only payloads.
FULLWIDTH_FALLBACK: Dict[str, str] = {
    "0": "\uff10",
    "1": "\uff11",
    "2": "\uff12",
    "3": "\uff13",
    "4": "\uff14",
    "5": "\uff15",
    "6": "\uff16",
    "7": "\uff17",
    "8": "\uff18",
    "9": "\uff19",
    "{": "\uff5b",
    "}": "\uff5d",
    "$": "\uff04",
    "<": "\uff1c",
    ">": "\uff1e",
    "=": "\uff1d",
    "/": "\uff0f",
    ".": "\uff0e",
    "%": "\uff05",
    "-": "\uff0d",
    ";": "\uff1b",
    "|": "\uff5c",
    "'": "\uff07",
    '"': "\uff02",
}


@dataclass(frozen=True)
class Variant:
    name: str
    value: str


def url_encode(value: str) -> str:
    # Encode every non-alphanumeric byte, including dots that urllib otherwise
    # treats as unreserved, so encoded variants are always distinct.
    pieces: List[str] = []
    for char in value:
        if char.isalnum():
            pieces.append(char)
        else:
            pieces.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
    return "".join(pieces)


def double_url_encode(value: str) -> str:
    return quote(url_encode(value), safe="")


def case_swap(value: str) -> str:
    swapped = value.swapcase()
    if swapped != value:
        return swapped
    # No ASCII letters (e.g. {{7*7}}): perturb the first digit/symbol with a
    # visually similar full-width glyph while keeping the variant distinct.
    for index, char in enumerate(value):
        if char.isascii() and char.isdigit() and char in FULLWIDTH_FALLBACK:
            return value[:index] + FULLWIDTH_FALLBACK[char] + value[index + 1 :]
    for index, char in enumerate(value):
        if char in FULLWIDTH_FALLBACK:
            return value[:index] + FULLWIDTH_FALLBACK[char] + value[index + 1 :]
    raise ValueError(f"cannot create distinct case-swapped variant for {value!r}")


def homoglyph(value: str) -> str:
    chars = list(value)
    for index, char in enumerate(chars):
        replacement = HOMOGLYPH_MAP.get(char)
        if replacement is not None:
            chars[index] = replacement
            return "".join(chars)
    # No Latin letter available: use the first mappable symbol/digit instead.
    for index, char in enumerate(chars):
        replacement = FULLWIDTH_FALLBACK.get(char)
        if replacement is not None:
            chars[index] = replacement
            return "".join(chars)
    raise ValueError(f"cannot create homoglyph variant for {value!r}")


VARIANT_FUNCTIONS: Dict[str, Callable[[str], str]] = {
    "original": lambda value: value,
    "url_encoded": url_encode,
    "double_url_encoded": double_url_encode,
    "case_swapped": case_swap,
    "homoglyph": homoglyph,
}


def make_variants(payload: str) -> List[Variant]:
    variants = [Variant(name, function(payload)) for name, function in VARIANT_FUNCTIONS.items()]
    values = [variant.value for variant in variants]
    if len(set(values)) != len(values):
        raise ValueError(f"variant collision detected for payload {payload!r}")
    return variants


def decode_variants(value: str) -> List[str]:
    """Return original, once-decoded and twice-decoded views of a request value."""

    once = unquote(value)
    twice = unquote(once)
    views = [value]
    if once != value:
        views.append(once)
    if twice != once:
        views.append(twice)
    return views
