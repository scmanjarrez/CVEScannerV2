# SPDX-License-Identifier: GPL-3.0-or-later

"""Check the production CPE parser against the reference parser.

Run from the db-manager directory with
``python -m tests.tools.check_cpe_corpus [RAW_DIR]``. The default RAW_DIR
is '../data/nvd-raw'.

The script walks the raw NVD pages, collects every string stored under
the 'cpeName' and 'criteria' keys, and compares db_manager.domain.cpe.split
with tests.reference_cpe.reference_split for each unique name. Both
parsers must return the same value, or raise the same ValueError message.
"""

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final, TypeGuard

from db_manager.domain.cpe import split
from db_manager.domain.models import CpeIdentity
from tests.reference_cpe import reference_split

DEFAULT_RAW_DIR: Final = Path("../data/nvd-raw")
PAGE_GLOBS: Final = ("cpes/full/page-*.json", "cves/full/page-*.json")
CPE_KEYS: Final = frozenset({"cpeName", "criteria"})
MAX_LISTED: Final = 20

Outcome = tuple[str, str]
"""Outcome kind ('ok' or exception name) and its textual result."""


class _Arguments(argparse.Namespace):
    """Typed namespace for the command-line arguments.

    Attributes:
        raw_dir: Directory holding the raw NVD 'cpes' and 'cves' pages.
    """

    raw_dir: Path


def _is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    """Check whether a decoded JSON node is an object.

    Args:
        value: Decoded JSON node.

    Returns:
        True when the node is a JSON object.
    """
    return isinstance(value, dict)


def _is_json_array(value: object) -> TypeGuard[list[object]]:
    """Check whether a decoded JSON node is an array.

    Args:
        value: Decoded JSON node.

    Returns:
        True when the node is a JSON array.
    """
    return isinstance(value, list)


def _collect_names(node: object, names: set[str]) -> None:
    """Add every CPE name found under the node to the set.

    Walks the decoded JSON recursively without any schema validation.

    Args:
        node: Decoded JSON node to walk.
        names: Set receiving the collected CPE names.
    """
    if _is_json_object(node):
        for key, value in node.items():
            if key in CPE_KEYS and isinstance(value, str):
                names.add(value)
            _collect_names(value, names)
    elif _is_json_array(node):
        for item in node:
            _collect_names(item, names)


def _collect_page_names(raw_dir: Path) -> tuple[int, set[str]]:
    """Collect unique CPE names from every raw page under raw_dir.

    Args:
        raw_dir: Directory holding the raw NVD 'cpes' and 'cves' pages.

    Returns:
        The number of page files read and the set of unique CPE names.
    """
    names: set[str] = set()
    files = 0
    for pattern in PAGE_GLOBS:
        for page in sorted(raw_dir.glob(pattern)):
            payload: object = json.loads(page.read_text(encoding="utf-8"))
            _collect_names(payload, names)
            files += 1
    return files, names


def _emit(line: str) -> None:
    """Write one report line to standard output.

    Args:
        line: Text to write, without a trailing newline.
    """
    sys.stdout.write(f"{line}\n")


def _outcome(
    parser: Callable[[str], CpeIdentity],
    name: str,
) -> Outcome:
    """Run one parser and capture its result or ValueError message.

    Args:
        parser: CPE parser under test.
        name: CPE name to parse.

    Returns:
        A pair with 'ok' and the repr of the result, or 'ValueError' and
        the exception message.
    """
    try:
        return ("ok", repr(parser(name)))
    except ValueError as err:
        return ("ValueError", str(err))


def _mismatches(names: Sequence[str]) -> list[str]:
    """Return a report line for every name where the parsers disagree.

    Args:
        names: CPE names to compare, in the order to report them.

    Returns:
        One multi-line report entry per disagreement.
    """
    entries: list[str] = []
    for name in names:
        production = _outcome(split, name)
        reference = _outcome(reference_split, name)
        if production == reference:
            continue
        entries.append(
            f"  - {name}\n"
            f"      split:     {production}\n"
            f"      reference: {reference}"
        )
    return entries


def main(argv: Sequence[str] | None = None) -> int:
    """Compare both CPE parsers over the raw NVD corpus.

    Args:
        argv: Optional argument list; defaults to the process arguments.

    Returns:
        0 when both parsers agree on every name, 1 when any differ, and 2
        when no raw pages are found.
    """
    parser = argparse.ArgumentParser(
        description="Compare CPE parsers over the raw NVD corpus.",
    )
    parser.add_argument(
        "raw_dir",
        nargs="?",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help="Directory with the raw 'cpes' and 'cves' pages.",
    )
    args = parser.parse_args(argv, namespace=_Arguments())

    files, names = _collect_page_names(args.raw_dir)
    if files == 0:
        _emit(f"No hay paginas 'page-*.json' en: {args.raw_dir}")
        return 2

    ordered = sorted(names)
    mismatches = _mismatches(ordered)
    _emit(f"Paginas leidas: {files}")
    _emit(f"Nombres CPE unicos: {len(ordered)}")
    _emit(f"Diferencias: {len(mismatches)}")
    for entry in mismatches[:MAX_LISTED]:
        _emit(entry)
    if len(mismatches) > MAX_LISTED:
        _emit(f"  ... {len(mismatches) - MAX_LISTED} diferencias mas")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
