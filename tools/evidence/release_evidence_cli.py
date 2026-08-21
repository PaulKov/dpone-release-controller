"""Permanent tombstone for the retired pre-broker release writer.

The historical command could write Backblaze B2 evidence and mutate GitHub.
Its implementation has been removed from the current tree. This entry point
exists only to fail closed with a migration message for old operator commands.
"""

from __future__ import annotations

import argparse

QUARANTINE_MESSAGE = (
    "PERMANENTLY QUARANTINED: the legacy release writer was removed; "
    "use only a separately reviewed, activation-bound controller"
)


def build_parser() -> argparse.ArgumentParser:
    """Build the read-only compatibility parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arguments", nargs="*", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Reject every non-help invocation before loading external code."""

    parser = build_parser()
    parser.parse_known_args(argv)
    parser.error(QUARANTINE_MESSAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
