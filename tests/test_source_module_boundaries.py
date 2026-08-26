"""Enforce reviewable Python module boundaries across the controller tree."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = ("scripts", "tests", "tools")
MAX_PHYSICAL_LINES = 400
MAX_NONBLANK_LINES = 350

# No source module is grandfathered. If a future migration temporarily needs an
# exception, it must name one exact path and the test below will force removal
# as soon as that module returns under both caps.
TODO_EXCLUSIONS: dict[str, str] = {}


def _python_modules() -> list[Path]:
    """Return deterministic repository-relative Python source paths."""

    return sorted(
        path
        for directory in SOURCE_DIRECTORIES
        for path in (REPOSITORY_ROOT / directory).rglob("*.py")
        if "__pycache__" not in path.parts
    )


def _line_counts(path: Path) -> tuple[int, int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return len(lines), sum(bool(line.strip()) for line in lines)


class SourceModuleBoundaryTests(unittest.TestCase):
    """Keep implementation and test modules small enough for focused review."""

    def test_python_modules_respect_physical_and_nonblank_caps(self) -> None:
        violations: list[str] = []
        active_exclusions: set[str] = set()

        for path in _python_modules():
            relative = path.relative_to(REPOSITORY_ROOT).as_posix()
            physical, nonblank = _line_counts(path)
            if physical <= MAX_PHYSICAL_LINES and nonblank <= MAX_NONBLANK_LINES:
                continue
            if relative in TODO_EXCLUSIONS:
                active_exclusions.add(relative)
                continue
            violations.append(
                f"{relative}: {physical} physical / {nonblank} nonblank lines"
            )

        stale_exclusions = sorted(set(TODO_EXCLUSIONS) - active_exclusions)
        if stale_exclusions:
            violations.extend(
                f"{path}: obsolete TODO exclusion must be removed"
                for path in stale_exclusions
            )

        self.assertEqual(
            violations,
            [],
            "Python module boundary violations:\n" + "\n".join(violations),
        )

    def test_production_modules_never_import_test_authority(self) -> None:
        violations: list[str] = []
        for directory in ("scripts", "tools"):
            for path in sorted((REPOSITORY_ROOT / directory).rglob("*.py")):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    imported: tuple[str, ...] = ()
                    if isinstance(node, ast.Import):
                        imported = tuple(alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module is not None:
                        imported = (node.module,)
                    if any(
                        name == "tests" or name.startswith("tests.")
                        for name in imported
                    ):
                        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
                        violations.append(f"{relative}:{node.lineno}")
        self.assertEqual(
            violations,
            [],
            "Production authority must not import tests:\n" + "\n".join(violations),
        )


if __name__ == "__main__":
    unittest.main()
