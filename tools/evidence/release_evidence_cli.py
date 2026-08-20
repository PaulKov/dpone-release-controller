"""PERMANENTLY QUARANTINED pre-broker release evidence CLI.

There is no compatibility flag. The activation-bound broker v2 protocol is
the only release-state writer; this command cannot load credentials or mutate
GitHub, PyPI, B2, or a local test stream.
"""

from __future__ import annotations

import argparse
from typing import Any, Never

from tools.evidence.release_legacy_writer_guard import disabled


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arguments", nargs="*", help=argparse.SUPPRESS)
    parser.parse_known_args(argv)
    parser.error("PERMANENTLY QUARANTINED: use the activation-bound broker v2 protocol")
    return 2


def _load_runtime_modules(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy evidence CLI runtime")


if __name__ == "__main__":
    raise SystemExit(main())
