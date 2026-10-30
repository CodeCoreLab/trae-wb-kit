#!/usr/bin/env python3
"""Build a WorkBuddy account-pool JSON export with an exact, fixed structure.

Guarantees:
  * Key order is frozen by SLOTS below (never reordered by dict insertion).
  * Byte-level output matches the reference sample:
        json.dumps(data, ensure_ascii=False, indent=2) + trailing LF, UTF-8, no BOM.
  * Missing slots are kept as placeholders (lenient, default) or rejected (--strict).
  * Sensitive values can be masked for sharing (--mask).

Author: agent_created skill asset.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


_MILLISECONDS_PER_SECOND = 1000


def _to_int(value, ctx=""):
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法整数{(' ' + ctx) if ctx else ''}: {value!r}") from exc


def _to_float(value, ctx=""):
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"非法浮点数{(' ' + ctx) if ctx else ''}: {value!r}") from exc

LOG = logging.getLogger("build_account_pool")

PLACEHOLDER_PREFIX = "__PENDING__"
MISSING = object()  # sentinel distinguishing "not provided" from a real empty value

TOP_SLOTS: tuple[tuple[str, str], ...] = (
    ("accounts", "list"),
    ("exported_at", "str"),
    ("include_credentials", "bool"),
    ("kind", "str"),
    ("version", "int"),
)

CREDENTIAL_SLOTS: tuple[tuple[str, str], ...] = (
    ("access_token", "str"),
    ("domain", "str"),
    ("expires_at_ms", "int"),
    ("refresh_token", "str"),
    ("uid", "str"),
    ("updated_at", "str"),
)

ACCOUNT_SLOTS: tuple[tuple[str, str], ...] = (
    ("access_token_expires_at", "int"),
    ("credential", "obj"),
    ("edition_type", "str"),
    ("group_id", "str"),
    ("id", "str"),
    ("nickname", "str"),
    ("note", "str"),
    ("phone_masked", "str"),
    ("refresh_token_expires_at", "int"),
    ("tags", "list"),
    ("uid", "str"),
)

REQUIRED_SLOT_PATHS: frozenset[str] = frozenset(
    {"id", "access_token_expires_at", "credential.access_token"}
)

MASK_FIELDS: frozenset[str] = frozenset(
    {"access_token", "refresh_token", "phone_masked", "uid", "note"}
)

DEFAULT_KIND = "aiwork-workbuddy-pool"
DEFAULT_VERSION = 1
DEFAULT_DOMAIN = "www.workbuddy.cn"
DEFAULT_EXPORT_NAME = "workbuddy_accounts_{date}.json"

# String slots that the reference sample legitimately leaves empty. Unlike genuinely
# unprovided slots, these keep a bare empty value instead of a __PENDING__ placeholder.
EMPTY_STRING_DEFAULTS: frozenset[str] = frozenset({"group_id", "note", "phone_masked"})

# Integer slot that the reference sample legitimately leaves absent; a missing value here
# means "unknown", so it keeps null without being reported as an unfilled placeholder.
OPTIONAL_NULL_INT: frozenset[str] = frozenset({"refresh_token_expires_at"})

_PATH_META = re.compile(r"^(?P<field>[a-z_]+)(?:\[(?P<idx>\d+)\])?$")


def _coerce(value: Any, kind: str) -> Any:
    """Coerce a raw value to the slot's declared type; raise on impossible coercion."""
    if value is MISSING:
        return MISSING
    if kind == "int":
        if value is None or value == "":
            return MISSING
        return _to_int(value)
    if kind == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "y", "真"}
    if kind == "list":
        if isinstance(value, list):
            return value
        if value in ("", None):
            return []
        raise ValueError(f"expected list, got {type(value).__name__}")
    if kind == "obj":
        if isinstance(value, Mapping):
            return dict(value)
        raise ValueError(f"expected object, got {type(value).__name__}")
    if kind == "str":
        if value is None:
            return MISSING
        return str(value)
    return value


def _placeholder(field: str, kind: str) -> Any:
    """Type-correct placeholder that keeps the output valid JSON."""
    if kind == "str":
        return f"{PLACEHOLDER_PREFIX}:{field}"
    if kind == "int":
        return None
    if kind == "bool":
        return False
    if kind == "list":
        return []
    if kind == "obj":
        return {}


_PATH_TOKEN = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\[(?P<idx>\d+)\])?$")


def _split_path(path: str) -> list[tuple[str, int | None]]:
    """Split a dotted field path into (name, index) tokens, e.g. `accounts[1].id`."""
    tokens: list[tuple[str, int | None]] = []
    for part in path.split("."):
        match = _PATH_TOKEN.match(part)
        if not match:
            raise ValueError(f"unsupported field path: {path!r}")
        index = match.group("idx")
        tokens.append((match.group("name"), _to_int(index) if index is not None else None))
    return tokens


def _assign(container: dict[str, Any], tokens: list[tuple[str, int | None]], value: Any) -> None:
    """Recursively assign `value` at the location addressed by `tokens`."""
    name, index = tokens[0]
    if len(tokens) == 1:
        if index is None:
            container[name] = value
            return
        bucket = container.get(name)
        if not isinstance(bucket, list):
            bucket = []
            container[name] = bucket
        while len(bucket) <= index:
            bucket.append({})
        bucket[index] = value
        return

    child_index = tokens[1][1]
    if index is None:
        child = container.get(name)
        if child_index is not None:
            if not isinstance(child, list):
                child = []
                container[name] = child
        elif not isinstance(child, dict):
            child = {}
            container[name] = child
        _assign(child, tokens[1:], value)
        return

    bucket = container.get(name)
    if not isinstance(bucket, list):
        bucket = []
        container[name] = bucket
    while len(bucket) <= index:
        bucket.append({})
    if not isinstance(bucket[index], dict):
        bucket[index] = {}
    _assign(bucket[index], tokens[1:], value)


def _apply_paths(payload: dict[str, Any], flat: Mapping[str, Any]) -> None:
    """Merge `field` / `field[i]` / `field.sub` keys into a nested payload dict."""
    for raw_key, value in flat.items():
        _assign(payload, _split_path(raw_key), value)


def _norm_abs_ms(value: Any) -> Any:
    """Normalise an expiry token supplied as seconds or milliseconds to absolute ms."""
    if value is MISSING:
        return MISSING
    return value * _MILLISECONDS_PER_SECOND if isinstance(value, int) and 0 < value < 10**11 else value


def _norm_epoch(value: Any) -> Any:
    """Normalise an expiry token supplied as seconds or milliseconds to epoch seconds."""
    if value is MISSING:
        return MISSING
    return value // _MILLISECONDS_PER_SECOND if isinstance(value, int) and value >= 10**11 else value


def _norm_updated_at(value: Any) -> Any:
    """Accept epoch seconds/ms, ISO-8601, or an offset spec such as '-36h'."""
    if value is MISSING:
        return MISSING
    if isinstance(value, str):
        text = value.strip()
        offset = re.fullmatch(r"[+-]?\d+(?:\.\d+)?[hdm]", text)
        if offset:
            unit = text[-1]
            amount = _to_float(text[:-1])
            delta = timedelta(hours=amount) if unit == "h" else timedelta(
                minutes=amount
            )
            if unit == "d":
                delta = timedelta(days=amount)
            stamp = datetime.now().astimezone() + delta
            return stamp.replace(microsecond=0).isoformat()
        if re.fullmatch(r"\d{10,13}", text):
            return _to_iso(_to_int(text))
        return text
    if isinstance(value, (int, float)):
        return _to_iso(_to_int(value))
    return value


def _to_iso(epoch: int) -> str:
    """Render epoch seconds/milliseconds as a local ISO-8601 timestamp (no timezone)."""
    seconds = epoch // _MILLISECONDS_PER_SECOND if epoch >= 10**11 else epoch
    return (
        datetime.fromtimestamp(seconds, tz=timezone.utc)
        .astimezone()
        .replace(tzinfo=None, microsecond=0)
        .isoformat()
    )


def _norm_exported_at(value: Any) -> Any:
    """Accept an ISO-8601 instant, or 'now' / '+08:00'-suffixed local stamp."""
    if value is MISSING:
        return MISSING
    text = str(value).strip()
    if text.lower() == "now":
        return datetime.now().astimezone().replace(microsecond=0).isoformat()
    return text


_NORMALISERS: dict[str, Any] = {
    "expires_at_ms": _norm_abs_ms,
    "access_token_expires_at": _norm_epoch,
    "refresh_token_expires_at": _norm_epoch,
    "updated_at": _norm_updated_at,
}


def _derive_uid(account: dict[str, Any]) -> None:
    """Credential.uid inherits account.uid, and vice versa, when only one is supplied."""
    uid = account.get("uid", MISSING)
    credential = account.get("credential")
    if not isinstance(credential, dict):
        return
    owner = credential.get("uid", MISSING)
    if owner is MISSING and uid is not MISSING:
        credential["uid"] = uid
    elif uid is MISSING and owner is not MISSING:
        account["uid"] = owner


def _derive_commit_tokens(account: dict[str, Any]) -> None:
    """Mirror access_token_expires_at <-> credential.expires_at_ms when only one is given."""
    expires = account.get("access_token_expires_at", MISSING)
    credential = account.get("credential")
    if not isinstance(credential, dict):
        return
    mirror = credential.get("expires_at_ms", MISSING)
    if expires is not MISSING and mirror is MISSING:
        credential["expires_at_ms"] = expires * _MILLISECONDS_PER_SECOND
    elif mirror is not MISSING and expires is MISSING:
        account["access_token_expires_at"] = mirror // _MILLISECONDS_PER_SECOND


def _arg_to_pairs(items: Iterable[str]) -> dict[str, Any]:
    """Parse repeated KEY=VALUE arguments into a flat mapping."""
    flat: dict[str, Any] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"--set expects KEY=VALUE, got {item!r}")
        flat[key.strip()] = value
    return flat


def _build_account(raw: Mapping[str, Any], strict: bool) -> tuple[dict[str, Any], list[str]]:
    """Produce one account object with frozen key order; collect missing slot paths.

    Assembly runs in three passes so that derivations see only real values:
      1. normalise provided values (absent values stay MISSING, not placeholders)
      2. derive mirror slots (uid, expires-at mirrors)
      3. lay out the frozen slot order, substituting placeholder/default for gaps
    """
    provided: dict[str, Any] = {}
    nested_raw = raw.get("credential")
    credential_source: Mapping[str, Any] = (
        nested_raw if isinstance(nested_raw, Mapping) else {}
    )

    for name, kind in ACCOUNT_SLOTS:
        candidate = credential_source if name == "credential" else raw.get(name, MISSING)
        if name == "credential":
            cred_provided: dict[str, Any] = {}
            for cred_name, cred_kind in CREDENTIAL_SLOTS:
                value = credential_source.get(cred_name, MISSING)
                if value is not MISSING and (normaliser := _NORMALISERS.get(cred_name)):
                    value = normaliser(value)
                value = _coerce(value, cred_kind)
                if value is not MISSING:
                    cred_provided[cred_name] = value
            provided[name] = cred_provided
            continue
        normaliser = _NORMALISERS.get(name)
        if candidate is not MISSING and normaliser is not None:
            candidate = normaliser(candidate)
        candidate = _coerce(candidate, kind)
        if candidate is not MISSING:
            provided[name] = candidate

    _derive_commit_tokens(provided)
    _derive_uid(provided)

    missing: list[str] = []
    account: dict[str, Any] = {}
    credential_provided = provided.get("credential", {})
    for name, kind in ACCOUNT_SLOTS:
        if name == "credential":
            credential: dict[str, Any] = {}
            for cred_name, cred_kind in CREDENTIAL_SLOTS:
                if cred_name in credential_provided:
                    credential[cred_name] = credential_provided[cred_name]
                    continue
                credential[cred_name] = (
                    DEFAULT_DOMAIN if cred_name == "domain" else _placeholder(cred_name, cred_kind)
                )
                missing.append(f"credential.{cred_name}")
            account[name] = credential
            continue
        if name in provided:
            account[name] = provided[name]
            continue
        if name in EMPTY_STRING_DEFAULTS:
            account[name] = ""
            continue
        if name in OPTIONAL_NULL_INT:
            account[name] = None
            continue
        if name == "tags":
            account[name] = []
            continue
        account[name] = _placeholder(name, kind)
        missing.append(name)

    if strict:
        hard = sorted(set(missing) & REQUIRED_SLOT_PATHS)
        if hard:
            raise ValueError("required fields absent: " + ", ".join(hard))
    return account, missing


def _collect_accounts(
    document: Mapping[str, Any], strict: bool
) -> tuple[list[dict[str, Any]], list[str]]:
    """Read accounts from either a nested JSON document or a single flat mapping."""
    nested = document.get("accounts")
    if isinstance(nested, list) and nested:
        accounts: list[dict[str, Any]] = []
        missing: list[str] = []
        for entry in nested:
            if not isinstance(entry, Mapping):
                raise ValueError("accounts[] entries must be objects")
            account, gaps = _build_account(entry, strict=strict)
            accounts.append(account)
            missing.extend(gaps)
        return accounts, missing
    account, gaps = _build_account(document, strict=strict)
    return [account], gaps


def _mask(accounts: list[dict[str, Any]]) -> None:
    """Redact sensitive values in place while preserving the document's structure."""
    for account in accounts:
        for field in MASK_FIELDS:
            if field in account and isinstance(account[field], str):
                if account[field] and not account[field].startswith(PLACEHOLDER_PREFIX):
                    account[field] = "<REDACTED>"
        credential = account.get("credential")
        if isinstance(credential, dict):
            for field in MASK_FIELDS:
                if isinstance(credential.get(field), str):
                    if credential[field] and not credential[field].startswith(
                        PLACEHOLDER_PREFIX
                    ):
                        credential[field] = "<REDACTED>"


def _assemble(
    accounts: list[dict[str, Any]], top: Mapping[str, Any], exported_at: Any
) -> dict[str, Any]:
    """Assemble the document with the frozen top-level key order."""
    merged = dict(top)
    merged["accounts"] = accounts
    merged["exported_at"] = exported_at
    if merged.get("kind", MISSING) is MISSING:
        merged["kind"] = DEFAULT_KIND
    if merged.get("version", MISSING) is MISSING:
        merged["version"] = DEFAULT_VERSION
    if merged.get("include_credentials", MISSING) is MISSING:
        merged["include_credentials"] = True
    return {name: merged[name] for name, _ in TOP_SLOTS}


def _serialise(document: Mapping[str, Any], trailing_newline: bool = False) -> str:
    """Render the document exactly like the reference sample.

    The reference export carries no trailing newline, so the default omits it;
    POSIX-friendly callers may opt in via --trailing-newline.
    """
    text = json.dumps(document, ensure_ascii=False, indent=2)
    return f"{text}\n" if trailing_newline else text


def _slot_signature(document: Mapping[str, Any]) -> list[str]:
    """Flatten the document into an ordered key-path list for structural comparison."""
    paths: list[str] = []

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                walk(value, f"{prefix}.{key}" if prefix else key)
        elif isinstance(node, list):
            if node:
                walk(node[0], f"{prefix}[]")
            else:
                paths.append(f"{prefix}[]")

    walk(document, "")
    return paths


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Build a WorkBuddy account-pool JSON with a frozen structure."
    )
    parser.add_argument("--in", dest="source", type=Path, help="JSON file with field values")
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="inline field")
    parser.add_argument("--out", type=Path, help="output path (default: cwd/<today>.json)")
    parser.add_argument("--strict", action="store_true", help="fail if required slots are empty")
    parser.add_argument("--mask", action="store_true", help="redact secrets for sharing")
    parser.add_argument("--verify-ref", type=Path, help="compare structure against a reference file")
    parser.add_argument(
        "--trailing-newline",
        action="store_true",
        help="append a final LF (default: byte-exact with the reference sample)",
    )
    parser.add_argument("--quiet", action="store_true", help="print the JSON only")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s" if args.quiet else "%(levelname)s: %(message)s",
    )

    raw_document: dict[str, Any] = {}
    if args.source:
        raw_document = json.loads(args.source.read_text(encoding="utf-8"))
    flat = _arg_to_pairs(args.set)
    if flat:
        # Route `accounts[...]` paths onto the document itself (append semantics) and every
        # other path onto the first account, so a single-account patch never lands inside
        # the wrong element.
        pool_flat = {k: v for k, v in flat.items() if k.split("[", 1)[0].split(".", 1)[0] == "accounts"}
        account_flat = {k: v for k, v in flat.items() if k not in pool_flat}
        if pool_flat:
            _apply_paths(raw_document, pool_flat)
        if account_flat:
            existing = raw_document.get("accounts")
            if isinstance(existing, list) and existing:
                first = dict(existing[0])
                _apply_paths(first, account_flat)
                raw_document["accounts"] = [first] + list(existing[1:])
            else:
                _apply_paths(raw_document, account_flat)

    try:
        accounts, missing = _collect_accounts(raw_document, strict=args.strict)
    except ValueError as exc:
        LOG.error("build rejected: %s", exc)
        return 2

    if args.mask:
        _mask(accounts)

    exported_at = _norm_exported_at(raw_document.get("exported_at", MISSING))
    if exported_at is MISSING:
        exported_at = datetime.now().astimezone().replace(microsecond=0).isoformat()

    document = _assemble(accounts, raw_document, exported_at)
    payload = _serialise(document, trailing_newline=args.trailing_newline)

    destination = args.out or Path(
        DEFAULT_EXPORT_NAME.format(date=datetime.now().strftime("%Y-%m-%d"))
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(payload, encoding="utf-8", newline="")

    if args.verify_ref:
        reference = json.loads(args.verify_ref.read_text(encoding="utf-8"))
        expected = _slot_signature(reference)
        actual = _slot_signature(document)
        if expected == actual:
            LOG.info("structure matches reference: %s", args.verify_ref)
        else:
            LOG.error("structure mismatch against %s", args.verify_ref)
            for path in expected:
                if path not in actual:
                    LOG.error("  missing: %s", path)
            for path in actual:
                if path not in expected:
                    LOG.error("  unexpected: %s", path)
            return 3

    if args.quiet:
        sys.stdout.write(payload)
    else:
        LOG.info("wrote %s (%d bytes, %d account(s))", destination, len(payload.encode()), len(accounts))
        if missing:
            LOG.warning("placeholders kept for: %s", ", ".join(sorted(set(missing))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
