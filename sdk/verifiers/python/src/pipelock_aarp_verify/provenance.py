# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

"""Experimental, fixture-only evidence-provenance proof verifier.

This module deliberately has no production receipt integration.  It consumes
only the signed fixture wrapper used by the four verifier conformance gate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import struct
import unicodedata
from collections.abc import Iterable
from typing import Any
from urllib.parse import unquote_plus, unquote_to_bytes, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .number import IJSONNumber, StrictParseError, parse_json_strict

FIXTURE_FORMAT = "pipelock-evidence-provenance-verification-fixture/v1"
PROOF_VERSION = "pipelock-evidence-provenance-proof/v1"
PROFILE_DIGEST = (
    "sha256:8bc27d5d89e4e5ba3e0d1e68a25a3f0170f9a5ea2f19edf81a9a90bf82e23b3e"
)
GENESIS = "genesis"
TRUST_ROOTS = "fixture supplied; self-attested; not authenticated"
_MAX_INPUT = 2 << 20
_MAX_OUTPUT = 1 << 20
_OP_BYTES = {
    "identity": 1,
    "url_component": 2,
    "percent_decode": 3,
    "dlp_normalize": 4,
    "lowercase": 5,
    "invisible_strip": 6,
    "hex_decode": 7,
    "base32_decode": 8,
    "base64_decode": 9,
    "leetspeak": 10,
    "vowel_fold": 11,
}
_COMPONENT_BYTES = {
    "": 0,
    "url": 1,
    "hostname": 2,
    "path": 3,
    "query_key": 4,
    "query_value": 5,
}
_PROOF_KEYS = {"version", "transform_profile_digest", "sources", "producer"}
_SOURCE_KEYS = {"source_ordinal", "source_id", "recipe", "view_commitment", "matches"}
_MATCH_KEYS = {
    "match_ordinal",
    "byte_start",
    "byte_end",
    "match_class",
    "match_commitment",
}
_RECIPE_KEYS = {"transform_profile_digest", "operations"}
_OP_KEYS = {
    "kind",
    "component",
    "selector",
    "occurrence",
    "passes",
    "profile",
    "decode_padding",
}
_PRODUCER_KEYS = {"binary_digest", "ruleset_digest"}


class ProvenanceError(Exception):
    """A proof failure with a stable comparable-output stage."""

    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


def _exact_dict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProvenanceError("proof_structure", f"{label} has an invalid field set")
    return value


def _fields(
    value: Any, required: set[str], optional: set[str], label: str
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not set(value).issubset(required | optional)
    ):
        raise ProvenanceError("proof_structure", f"{label} has an invalid field set")
    return value


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProvenanceError("proof_structure", f"{label} must be a string")
    return value


def _uint(value: Any, label: str) -> int:
    if not isinstance(value, IJSONNumber) or not value.literal.isdigit():
        raise ProvenanceError("proof_structure", f"{label} must be an unsigned integer")
    result = int(value.literal)
    if result > (1 << 64) - 1:
        raise ProvenanceError("proof_structure", f"{label} exceeds uint64")
    return result


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProvenanceError("proof_structure", f"{label} must be a boolean")
    return value


def _utf8(value: str, label: str) -> bytes:
    try:
        return value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ProvenanceError("proof_structure", f"{label} is not UTF-8") from exc


def _b64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} is not base64") from exc


def _hex(value: Any, label: str, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not hex") from exc
    if raw.hex() != value or (size is not None and len(raw) != size):
        raise ValueError(f"{label} has an invalid length or spelling")
    return raw


def _digest(value: Any, label: str, prefix: str = "sha256:") -> str:
    text = _require_str(value, label)
    encoded = text.removeprefix(prefix)
    if (
        not text.startswith(prefix)
        or len(encoded) != 64
        or any(c not in "0123456789abcdef" for c in encoded)
    ):
        raise ProvenanceError("proof_structure", f"{label} is not a canonical digest")
    return text


def _frame(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _recipe_bytes(recipe: dict[str, Any]) -> bytes:
    profile = _require_str(recipe["transform_profile_digest"], "recipe profile")
    if profile == "":
        raise ProvenanceError("proof_structure", "missing transform profile digest")
    if profile != PROFILE_DIGEST:
        raise ProvenanceError("proof_structure", "unknown transform profile")
    operations = recipe["operations"]
    if not isinstance(operations, list):
        raise ProvenanceError("proof_structure", "recipe operations must be an array")
    result = (
        _frame(b"pipelock/evidence-provenance/recipe/v1")
        + _frame(_utf8(profile, "recipe profile"))
        + _frame(struct.pack(">Q", len(operations)))
    )
    for index, raw in enumerate(operations):
        operation = _fields(
            raw, {"kind"}, _OP_KEYS - {"kind"}, f"recipe operation {index}"
        )
        kind = _require_str(operation["kind"], "operation kind")
        component = _require_str(operation.get("component", ""), "operation component")
        selector = _require_str(operation.get("selector", ""), "operation selector")
        occurrence = _uint(
            operation.get("occurrence", IJSONNumber("0")), "operation occurrence"
        )
        passes = _uint(operation.get("passes", IJSONNumber("0")), "operation passes")
        profile_name = _require_str(operation.get("profile", ""), "operation profile")
        padding = _bool(
            operation.get("decode_padding", False), "operation decode_padding"
        )
        _validate_operation(
            kind, component, selector, occurrence, passes, profile_name, padding
        )
        encoded = b"".join(
            (
                _frame(bytes([_OP_BYTES[kind]])),
                _frame(bytes([_COMPONENT_BYTES[component]])),
                _frame(_utf8(selector, "operation selector")),
                _frame(struct.pack(">I", occurrence)),
                _frame(bytes([passes])),
                _frame(_utf8(profile_name, "operation profile")),
                _frame(bytes([1 if padding else 0])),
            )
        )
        result += _frame(encoded)
    return result


def _has_control(value: str) -> bool:
    # Go's unicode.IsControl is the Unicode Cc category, not every C* format
    # or private-use code point.
    return any(unicodedata.category(char) == "Cc" for char in value)


def _validate_operation(
    kind: str,
    component: str,
    selector: str,
    occurrence: int,
    passes: int,
    profile: str,
    padding: bool,
) -> None:
    if occurrence > 0xFFFFFFFF:
        raise ProvenanceError(
            "proof_structure", "operation occurrence exceeds uint32"
        )
    if kind not in _OP_BYTES:
        raise ProvenanceError("proof_structure", f"unknown operation {kind!r}")
    if component not in _COMPONENT_BYTES:
        raise ProvenanceError("proof_structure", f"unknown URL component {component!r}")
    if _has_control(selector):
        raise ProvenanceError(
            "proof_structure", f"selector for {kind} contains control character"
        )
    if _has_control(profile):
        raise ProvenanceError(
            "proof_structure", f"profile for {kind} contains control character"
        )
    none = (
        component == ""
        and selector == ""
        and occurrence == 0
        and passes == 0
        and profile == ""
        and not padding
    )
    if kind in {
        "identity",
        "lowercase",
        "invisible_strip",
        "leetspeak",
        "vowel_fold",
        "hex_decode",
    }:
        if not none:
            raise ProvenanceError(
                "proof_structure", f"unsupported operation parameter for {kind}"
            )
        return
    if kind == "url_component":
        if passes != 0 or profile != "" or padding:
            raise ProvenanceError(
                "proof_structure", "unsupported URL component parameter"
            )
        if component in {"url", "hostname", "path"} and (
            selector != "" or occurrence != 0
        ):
            raise ProvenanceError(
                "proof_structure", "unsupported URL selector or occurrence"
            )
        if component in {"query_key", "query_value"} and selector == "":
            raise ProvenanceError(
                "proof_structure", "query component is missing selector"
            )
        return
    if kind == "percent_decode":
        if (
            component
            or selector
            or occurrence
            or profile
            or padding
            or not 1 <= passes <= 4
        ):
            raise ProvenanceError(
                "proof_structure", "percent decode passes must be 1..4"
            )
        return
    if kind == "dlp_normalize":
        if profile != "pipelock-dlp-v1":
            raise ProvenanceError("proof_structure", f"unknown DLP profile {profile!r}")
        if component or selector or occurrence or passes or padding:
            raise ProvenanceError("proof_structure", "invalid DLP normalize parameters")
        return
    if kind in {"base32_decode", "base64_decode"} and (
        component or selector or occurrence or passes or profile
    ):
        raise ProvenanceError("proof_structure", "invalid base decoder parameters")


def _check_percent(value: str, label: str = "percent decode") -> None:
    for index, char in enumerate(value):
        if char == "%" and (
            index + 2 >= len(value)
            or any(
                c not in "0123456789abcdefABCDEF" for c in value[index + 1 : index + 3]
            )
        ):
            raise ProvenanceError("view_reproduction", f"{label}: malformed escape")


def _strip_invisible(value: str, *, preserve_whitespace: bool = True) -> str:
    keep = []
    for char in value:
        code = ord(char)
        if (
            code < 32 and (not preserve_whitespace or char not in "\t\n\r")
        ) or 127 <= code <= 159:
            continue
        if (
            code in {0xAD, 0x3164, 0xFEFF}
            or 0x115F <= code <= 0x1160
            or 0x200B <= code <= 0x200F
            or 0x202A <= code <= 0x202E
            or 0x2060 <= code <= 0x2064
            or 0x2066 <= code <= 0x2069
            or 0xFE00 <= code <= 0xFE0F
            or 0xFFF9 <= code <= 0xFFFB
            or 0xE0000 <= code <= 0xE007F
            or 0xE0100 <= code <= 0xE01EF
        ):
            continue
        keep.append(char)
    return "".join(keep)


_CONFUSABLES = str.maketrans(
    {
        "А": "A",
        "В": "B",
        "С": "C",
        "Е": "E",
        "Н": "H",
        "І": "I",
        "Ј": "J",
        "К": "K",
        "М": "M",
        "О": "O",
        "Р": "P",
        "Ѕ": "S",
        "Т": "T",
        "Х": "X",
        "а": "a",
        "в": "v",
        "е": "e",
        "н": "h",
        "і": "i",
        "к": "k",
        "м": "m",
        "о": "o",
        "р": "p",
        "с": "c",
        "т": "t",
        "у": "y",
        "х": "x",
        "ј": "j",
        "ѕ": "s",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "Օ": "O",
        "օ": "o",
        "Ս": "S",
        "ս": "s",
        "Լ": "L",
        "հ": "h",
        "ո": "n",
        "ռ": "n",
        "ա": "a",
        "Ꭺ": "A",
        "Ꭲ": "I",
        "Ꮲ": "P",
        "Ꮪ": "S",
        "Ꭱ": "E",
        "Ꮃ": "W",
        "Ꮤ": "T",
        "Ø": "O",
        "ø": "o",
        "Đ": "D",
        "đ": "d",
        "Ł": "L",
        "ł": "l",
        "Ħ": "H",
        "ħ": "h",
        "Ŧ": "T",
        "ŧ": "t",
        "ᴀ": "A",
        "ʙ": "B",
        "ᴄ": "C",
        "ᴅ": "D",
        "ᴇ": "E",
        "ꜰ": "F",
        "ɢ": "G",
        "ʜ": "H",
        "ɪ": "I",
        "ᴊ": "J",
        "ᴋ": "K",
        "ʟ": "L",
        "ᴍ": "M",
        "ɴ": "N",
        "ᴏ": "O",
        "ᴘ": "P",
        "ʀ": "R",
        "ꜱ": "S",
        "ᴛ": "T",
        "ᴜ": "U",
        "ᴠ": "V",
        "ᴡ": "W",
        "ʏ": "Y",
        "ᴢ": "Z",
    }
)


def _confusable_to_ascii(value: str) -> str:
    """Apply the profile's explicit map and its two alphabetic ranges."""
    mapped = value.translate(_CONFUSABLES)
    result = []
    for char in mapped:
        code = ord(char)
        if 0x1F170 <= code <= 0x1F189:
            result.append(chr(ord("A") + code - 0x1F170))
        elif 0x1F1E6 <= code <= 0x1F1FF:
            result.append(chr(ord("A") + code - 0x1F1E6))
        else:
            result.append(char)
    return "".join(result)


def _dlp_normalize(value: str) -> str:
    value = _strip_invisible(value, preserve_whitespace=False)
    value = "".join(
        ""
        if ord(char)
        in {
            0xA0,
            0x1680,
            0x180E,
            *range(0x2000, 0x200B),
            0x2028,
            0x2029,
            0x202F,
            0x205F,
            0x3000,
        }
        else char
        for char in value
    )
    value = _confusable_to_ascii(unicodedata.normalize("NFKC", value))
    return "".join(
        char
        for char in unicodedata.normalize("NFD", value)
        if unicodedata.category(char) != "Mn"
    )


def _url_component(value: str, component: str, selector: str, occurrence: int) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ProvenanceError("view_reproduction", "invalid absolute URL") from exc
    if not parsed.scheme or not parsed.netloc:
        raise ProvenanceError("view_reproduction", "invalid absolute URL")
    if component == "url":
        return value
    if component == "hostname":
        return parsed.hostname or ""
    if component == "path":
        return parsed.path
    _check_percent(parsed.query, "query parse")
    pairs: list[tuple[str, str]] = []
    for part in parsed.query.split("&"):
        key, sep, item = part.partition("=")
        pairs.append(
            (
                unquote_plus(key, encoding="utf-8", errors="strict"),
                unquote_plus(item if sep else "", encoding="utf-8", errors="strict"),
            )
        )
    values = [item for key, item in pairs if key == selector]
    if occurrence >= len(values):
        raise ProvenanceError(
            "view_reproduction", f"query occurrence {occurrence} unavailable"
        )
    return selector if component == "query_key" else values[occurrence]


def _apply_recipe(recipe: dict[str, Any], source: bytes) -> bytes:
    try:
        value = source.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("view_reproduction", "source is invalid UTF-8") from exc
    if len(source) > _MAX_INPUT:
        raise ProvenanceError("view_reproduction", "source exceeds profile byte limit")
    _recipe_bytes(recipe)  # validates parameters and profile before execution.
    for raw in recipe["operations"]:
        kind = raw["kind"]
        if kind == "url_component":
            value = _url_component(
                value,
                raw.get("component", ""),
                raw.get("selector", ""),
                int(raw.get("occurrence", IJSONNumber("0")).literal),
            )
        elif kind == "percent_decode":
            for _ in range(int(raw.get("passes", IJSONNumber("0")).literal)):
                _check_percent(value)
                try:
                    value = unquote_to_bytes(value).decode("utf-8", "strict")
                except UnicodeDecodeError as exc:
                    raise ProvenanceError(
                        "view_reproduction", "output: invalid UTF-8"
                    ) from exc
        elif kind == "dlp_normalize":
            value = _dlp_normalize(value)
        elif kind == "lowercase":
            value = value.lower()
        elif kind == "invisible_strip":
            value = _strip_invisible(value)
        elif kind == "hex_decode":
            try:
                decoded = bytes.fromhex(value)
            except ValueError as exc:
                raise ProvenanceError("view_reproduction", "hex decode failed") from exc
            if decoded.hex() != value:
                raise ProvenanceError(
                    "view_reproduction", "hex decode: non-canonical encoding"
                )
            try:
                value = decoded.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise ProvenanceError(
                    "view_reproduction", "hex decode output: invalid UTF-8"
                ) from exc
        elif kind in {"base32_decode", "base64_decode"}:
            padding = bool(raw.get("decode_padding", False))
            try:
                if kind == "base32_decode":
                    decoded = (
                        base64.b32decode(value, casefold=False)
                        if padding
                        else base64.b32decode(
                            value + "=" * ((8 - len(value) % 8) % 8), casefold=False
                        )
                    )
                    encoded = (
                        base64.b32encode(decoded).decode("ascii")
                        if padding
                        else base64.b32encode(decoded).decode("ascii").rstrip("=")
                    )
                else:
                    decoded = (
                        base64.b64decode(value, validate=True)
                        if padding
                        else base64.b64decode(
                            value + "=" * ((4 - len(value) % 4) % 4), validate=True
                        )
                    )
                    encoded = (
                        base64.b64encode(decoded).decode("ascii")
                        if padding
                        else base64.b64encode(decoded).decode("ascii").rstrip("=")
                    )
            except (binascii.Error, ValueError) as exc:
                label = kind.removesuffix("_decode")
                raise ProvenanceError(
                    "view_reproduction", f"{label} decode failed"
                ) from exc
            if encoded != value:
                label = kind.removesuffix("_decode")
                raise ProvenanceError(
                    "view_reproduction", f"{label} decode: non-canonical encoding"
                )
            try:
                value = decoded.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                label = kind.removesuffix("_decode")
                raise ProvenanceError(
                    "view_reproduction", f"{label} decode output: invalid UTF-8"
                ) from exc
        elif kind == "leetspeak":
            value = value.translate(
                str.maketrans(
                    {
                        "0": "o",
                        "1": "i",
                        "3": "e",
                        "4": "a",
                        "5": "s",
                        "7": "t",
                        "@": "a",
                        "$": "s",
                    }
                )
            )
        elif kind == "vowel_fold":
            value = value.translate(str.maketrans("aeiouAEIOU", "aaaaaAAAAA"))
        encoded_value = value.encode("utf-8", "strict")
        if len(encoded_value) > _MAX_OUTPUT:
            raise ProvenanceError(
                "view_reproduction", "view exceeds profile byte limit"
            )
    return value.encode("utf-8", "strict")


def _validate_intervals(view: bytes, matches: list[tuple[int, int]]) -> None:
    """Validate the proof profile's byte-coordinate interval invariants."""
    try:
        view.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ProvenanceError("location", "view: invalid UTF-8") from exc
    previous_start = previous_end = -1
    for start, end in matches:
        if end <= start:
            raise ProvenanceError(
                "location", "byte end must be greater than byte start"
            )
        if end > len(view):
            raise ProvenanceError("location", "interval out of bounds")
        if (start != 0 and view[start] & 0xC0 == 0x80) or (
            end != len(view) and view[end] & 0xC0 == 0x80
        ):
            raise ProvenanceError("location", "interval splits UTF-8 code point")
        if previous_start >= 0:
            if start < previous_start:
                raise ProvenanceError("location", "intervals are unsorted")
            if start == previous_start:
                raise ProvenanceError("location", "duplicate interval start")
            if start < previous_end:
                raise ProvenanceError("location", "intervals overlap")
        previous_start, previous_end = start, end


def _commit(key: bytes, domain: str, parts: Iterable[bytes]) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(_frame(domain.encode("ascii")))
    for part in parts:
        mac.update(_frame(part))
    return "hmac-sha256:" + mac.hexdigest()


def _output(
    signature: str = "not_checked",
    chain: str = "not_checked",
    artifacts: str = "attested_unchecked",
    source_commitment: str = "not_checked",
    view_reproduction: str = "not_checked",
    location: str = "not_checked",
    match_commitment: str = "not_checked",
    overall: str = "incomplete",
    failure_stage: str = "",
) -> dict[str, Any]:
    value = {
        "trust_roots": TRUST_ROOTS,
        "authenticated_provenance": False,
        "signature": signature,
        "chain": chain,
        "artifacts": artifacts,
        "source_commitment": source_commitment,
        "view_reproduction": view_reproduction,
        "location": location,
        "match_commitment": match_commitment,
        "overall": overall,
    }
    if failure_stage:
        value["failure_stage"] = failure_stage
    return value


def _invalid(stage: str, current: dict[str, Any]) -> dict[str, Any]:
    if stage in current:
        current[stage] = "invalid" if stage in {"signature", "chain"} else "mismatch"
    if stage == "view_commitment":
        # The report has a single commitment-result field. Its mismatch is
        # retained while failure_stage identifies which commitment failed.
        current["match_commitment"] = "mismatch"
    current["overall"] = "invalid"
    current["failure_stage"] = stage
    return current


def _parse_signed(signed: bytes) -> dict[str, Any]:
    try:
        value = parse_json_strict(signed)
    except (UnicodeDecodeError, StrictParseError) as exc:
        raise ProvenanceError(
            "proof_structure", "signed bytes are not strict UTF-8 JSON"
        ) from exc
    return _exact_dict(
        value,
        {"chain_seq", "chain_prev_hash", "critical_features", "proof"},
        "signed assertion",
    )


def _verify_entry(
    entry: Any,
    index: int,
    public_key: bytes,
    commitment_key: bytes | None,
    sources: dict[str, bytes],
    binary: bytes | None,
    ruleset: bytes | None,
    previous_signed: bytes | None,
) -> dict[str, Any]:
    result = _output()
    try:
        entry = _exact_dict(entry, {"signed_b64", "signature"}, "entry")
        signed = _b64(entry["signed_b64"], "signed_b64")
        signed_object = _parse_signed(signed)
        signature = _require_str(entry["signature"], "signature")
        if not signature.startswith("ed25519:"):
            raise ValueError("signature prefix")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _hex(signature[8:], "signature", 64), signed
        )
        result["signature"] = "verified"
    except ProvenanceError:
        return _invalid("proof_structure", result)
    except (InvalidSignature, ValueError, TypeError):
        return _invalid("signature", result)
    try:
        sequence = _uint(signed_object["chain_seq"], "chain_seq")
        previous = _require_str(signed_object["chain_prev_hash"], "chain_prev_hash")
        expected_previous = (
            GENESIS
            if previous_signed is None
            else "sha256:" + hashlib.sha256(previous_signed).hexdigest()
        )
        if sequence != index or previous != expected_previous:
            return _invalid("chain", result)
        result["chain"] = "verified"
    except ProvenanceError:
        return _invalid("chain", result)
    critical = signed_object["critical_features"]
    if not isinstance(critical, list) or critical != ["evidence_provenance"]:
        return _invalid("critical_features", result)
    try:
        proof = _exact_dict(signed_object["proof"], _PROOF_KEYS, "proof")
        if _require_str(proof["version"], "proof version") != PROOF_VERSION:
            raise ProvenanceError("proof_structure", "unsupported proof version")
        if (
            _require_str(proof["transform_profile_digest"], "proof profile")
            != PROFILE_DIGEST
        ):
            raise ProvenanceError("proof_structure", "unknown proof profile")
        producer = _fields(proof["producer"], set(), _PRODUCER_KEYS, "producer")
        source_list = proof["sources"]
        if not isinstance(source_list, list):
            raise ProvenanceError("proof_structure", "proof sources must be an array")
        parsed_sources = []
        source_ids: set[str] = set()
        ordinals: set[int] = set()
        last_ordinal = -1
        for source in source_list:
            source = _fields(source, _SOURCE_KEYS - {"matches"}, {"matches"}, "source")
            source_id = _require_str(source["source_id"], "source id")
            _utf8(source_id, "source id")
            ordinal = _uint(source["source_ordinal"], "source ordinal")
            recipe = _exact_dict(source["recipe"], _RECIPE_KEYS, "recipe")
            recipe_bytes = _recipe_bytes(recipe)
            if (
                _require_str(recipe["transform_profile_digest"], "recipe profile")
                != proof["transform_profile_digest"]
            ):
                raise ProvenanceError(
                    "proof_structure", "recipe profile differs from proof"
                )
            view_commitment = _digest(
                source["view_commitment"], "view commitment", "hmac-sha256:"
            )
            if (
                not source_id
                or source_id in source_ids
                or ordinal in ordinals
                or ordinal <= last_ordinal
            ):
                raise ProvenanceError(
                    "proof_structure", "source identities or ordinals are invalid"
                )
            matches = source.get("matches", [])
            if not isinstance(matches, list):
                raise ProvenanceError("proof_structure", "matches must be an array")
            parsed_matches = []
            previous_start = previous_end = previous_ordinal = -1
            for match in matches:
                match = _exact_dict(match, _MATCH_KEYS, "match")
                match_ordinal = _uint(match["match_ordinal"], "match ordinal")
                start = _uint(match["byte_start"], "byte start")
                end = _uint(match["byte_end"], "byte end")
                match_class = _require_str(match["match_class"], "match class")
                _utf8(match_class, "match class")
                match_commitment = _digest(
                    match["match_commitment"], "match commitment", "hmac-sha256:"
                )
                if (
                    end <= start
                    or match_ordinal <= previous_ordinal
                    or start <= previous_start
                    or start < previous_end
                ):
                    raise ProvenanceError(
                        "proof_structure", "match ordering or interval is invalid"
                    )
                parsed_matches.append(
                    (match_ordinal, start, end, match_class, match_commitment)
                )
                previous_start, previous_end, previous_ordinal = (
                    start,
                    end,
                    match_ordinal,
                )
            parsed_sources.append(
                (
                    ordinal,
                    source_id,
                    recipe,
                    recipe_bytes,
                    view_commitment,
                    parsed_matches,
                )
            )
            source_ids.add(source_id)
            ordinals.add(ordinal)
            last_ordinal = ordinal
    except ProvenanceError:
        return _invalid("proof_structure", result)
    binary_digest = producer.get("binary_digest")
    ruleset_digest = producer.get("ruleset_digest")
    try:
        if binary_digest is not None:
            _digest(binary_digest, "binary digest")
        if ruleset_digest is not None:
            _digest(ruleset_digest, "ruleset digest")
    except ProvenanceError:
        return _invalid("proof_structure", result)
    binary_mismatch = (
        binary_digest is not None
        and binary is not None
        and binary_digest != "sha256:" + hashlib.sha256(binary).hexdigest()
    )
    ruleset_mismatch = (
        ruleset_digest is not None
        and ruleset is not None
        and ruleset_digest != "sha256:" + hashlib.sha256(ruleset).hexdigest()
    )
    if binary_mismatch or ruleset_mismatch:
        return _invalid("artifacts", result)
    if (binary_digest is not None and binary is None) or (
        ruleset_digest is not None and ruleset is None
    ):
        result["artifacts"] = "attested_unchecked"
    else:
        result["artifacts"] = "matched"
    unavailable_source = False
    for (
        ordinal,
        source_id,
        recipe,
        recipe_bytes,
        view_commitment,
        matches,
    ) in parsed_sources:
        source = sources.get(source_id)
        if source is None:
            unavailable_source = True
            continue
        try:
            view = _apply_recipe(recipe, source)
        except (ProvenanceError, UnicodeError):
            return _invalid("view_reproduction", result)
        result["view_reproduction"] = "reproduced"
        for _match_ordinal, start, end, _match_class, _match_commitment in matches:
            if (
                end > len(view)
                or (start != 0 and view[start] & 0xC0 == 0x80)
                or (end != len(view) and view[end] & 0xC0 == 0x80)
            ):
                return _invalid("location", result)
            result["location"] = "exact_coordinates"
        if commitment_key is not None:
            computed_view = _commit(
                commitment_key,
                "pipelock/evidence-provenance/view/v1",
                [
                    struct.pack(">Q", ordinal),
                    source_id.encode(),
                    proof["transform_profile_digest"].encode(),
                    recipe_bytes,
                    view,
                ],
            )
            if not hmac.compare_digest(computed_view, view_commitment):
                if unavailable_source:
                    result["view_reproduction"] = "not_checked"
                    result["location"] = "not_checked"
                return _invalid("view_commitment", result)
            for match_ordinal, start, end, match_class, match_commitment in matches:
                computed_match = _commit(
                    commitment_key,
                    "pipelock/evidence-provenance/match/v1",
                    [
                        source_id.encode(),
                        proof["transform_profile_digest"].encode(),
                        recipe_bytes,
                        view_commitment.encode(),
                        struct.pack(">Q", match_ordinal),
                        struct.pack(">Q", start),
                        struct.pack(">Q", end),
                        match_class.encode(),
                    ],
                )
                if not hmac.compare_digest(computed_match, match_commitment):
                    if unavailable_source:
                        result["view_reproduction"] = "not_checked"
                        result["location"] = "not_checked"
                    return _invalid("match_commitment", result)
            result["match_commitment"] = "opened"
    if unavailable_source:
        # A missing source leaves the receipt incomplete, but does not prevent
        # us from detecting a mismatch in a later source that is available.
        result["view_reproduction"] = "not_checked"
        result["location"] = "not_checked"
        result["match_commitment"] = "not_checked"
    return result


def verify_fixture(data: bytes) -> tuple[dict[str, Any], int]:
    """Verify the fixture wrapper and return one aggregate staged report."""
    try:
        wrapper = parse_json_strict(data)
        wrapper = _exact_dict(wrapper, {"format", "entries", "verification"}, "fixture")
        if _require_str(wrapper["format"], "format") != FIXTURE_FORMAT:
            raise ValueError("unsupported fixture format")
        entries = wrapper["entries"]
        verification = _fields(
            wrapper["verification"],
            {"signer_public_key_hex"},
            {"commitment_key_hex", "sources", "binary_b64", "ruleset_b64"},
            "verification",
        )
        source_inputs = verification.get("sources", [])
        if (
            not isinstance(entries, list)
            or not entries
            or not isinstance(source_inputs, list)
        ):
            raise ValueError("entries and sources must be arrays")
        public_key = _hex(
            verification["signer_public_key_hex"], "signer public key", 32
        )
        commitment_key = (
            None
            if verification.get("commitment_key_hex") is None
            else _hex(verification["commitment_key_hex"], "commitment key")
        )
        if commitment_key is not None and len(commitment_key) < 32:
            raise ValueError("commitment key is too short")
        sources: dict[str, bytes] = {}
        for item in source_inputs:
            item = _exact_dict(item, {"source_id", "bytes_b64"}, "source input")
            source_id = _require_str(item["source_id"], "source input id")
            if not source_id or source_id in sources:
                raise ValueError("source input IDs must be unique")
            sources[source_id] = _b64(item["bytes_b64"], "source bytes")
        binary = (
            None
            if verification.get("binary_b64") is None
            else _b64(verification["binary_b64"], "binary")
        )
        ruleset = (
            None
            if verification.get("ruleset_b64") is None
            else _b64(verification["ruleset_b64"], "ruleset")
        )
    except (StrictParseError, UnicodeDecodeError, ValueError, ProvenanceError):
        return _invalid("proof_structure", _output()), 1
    aggregate = _output(signature="verified", chain="verified", artifacts="matched")
    all_reproduced = True
    all_located = True
    all_commitments_opened = True
    previous_signed = None
    for index, entry in enumerate(entries):
        result = _verify_entry(
            entry,
            index,
            public_key,
            commitment_key,
            sources,
            binary,
            ruleset,
            previous_signed,
        )
        if result["overall"] == "invalid":
            return result, 1
        if result["artifacts"] == "attested_unchecked":
            aggregate["artifacts"] = "attested_unchecked"
        all_reproduced = all_reproduced and result["view_reproduction"] == "reproduced"
        all_located = all_located and result["location"] == "exact_coordinates"
        all_commitments_opened = (
            all_commitments_opened and result["match_commitment"] == "opened"
        )
        try:
            previous_signed = (
                _b64(entry["signed_b64"], "signed_b64")
                if isinstance(entry, dict)
                else None
            )
        except ValueError:
            previous_signed = None
    aggregate["view_reproduction"] = "reproduced" if all_reproduced else "not_checked"
    aggregate["location"] = "exact_coordinates" if all_located else "not_checked"
    aggregate["match_commitment"] = (
        "opened" if all_commitments_opened else "not_checked"
    )
    return aggregate, 0


def compact_fixture_json(data: bytes) -> tuple[str, int]:
    """Render the exact compact JSON consumed by the differential gate."""
    output, exit_code = verify_fixture(data)
    return json.dumps(output, separators=(",", ":"), ensure_ascii=False), exit_code
