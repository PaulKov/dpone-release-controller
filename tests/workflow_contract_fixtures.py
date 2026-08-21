"""Frozen semantic allowlists for the only accepted GitHub workflows."""

from __future__ import annotations

from typing import Any

CHECKOUT_ACTION = "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
SETUP_NODE_ACTION = "actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444"
SETUP_PYTHON_ACTION = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
SETUP_UV_ACTION = "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78"
UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
)

_IDENTITY_ENV = {
    "GITHUB_EVENT_NAME": "${{ github.event_name }}",
    "GITHUB_REF": "${{ github.ref }}",
    "GITHUB_REPOSITORY": "${{ github.repository }}",
    "GITHUB_REPOSITORY_ID": "${{ github.repository_id }}",
    "GITHUB_RUN_ID": "${{ github.run_id }}",
    "GITHUB_SHA": "${{ github.sha }}",
    "GITHUB_WORKFLOW_REF": "${{ github.workflow_ref }}",
}


def _shell(*lines: str) -> str:
    """Build the exact literal-block value expected from the YAML parser."""

    return "\n".join(lines)


EXPECTED_CONTROLLER_WORKFLOW: dict[str, Any] = {
    "name": "Release controller quarantine",
    "on": {
        "workflow_dispatch": {
            "inputs": {
                "tag": {
                    "description": "Canonical vSemVer tag (empty = per-run quarantine tag)",
                    "required": False,
                    "default": "",
                },
                "ttl_seconds": {
                    "description": (
                        "Future lease TTL in seconds (validated, never acquired here)"
                    ),
                    "required": True,
                    "default": "900",
                },
                "mode": {
                    "description": "Non-mutating validation mode; live is fail-closed",
                    "required": True,
                    "default": "dry-run",
                    "type": "choice",
                    "options": ["dry-run", "live"],
                },
            }
        }
    },
    "permissions": {},
    "concurrency": {
        "group": "release-controller-quarantine",
        "cancel-in-progress": False,
    },
    "jobs": {
        "preflight": {
            "name": "Validate dispatch under controller quarantine",
            "runs-on": "ubuntu-latest",
            "permissions": {"contents": "read"},
            "outputs": {
                "mode": "${{ steps.preflight.outputs.mode }}",
                "tag": "${{ steps.preflight.outputs.tag }}",
                "ttl_seconds": "${{ steps.preflight.outputs.ttl_seconds }}",
            },
            "steps": [
                {
                    "name": "Checkout controller policy only",
                    "uses": CHECKOUT_ACTION,
                    "with": {"persist-credentials": False},
                },
                {
                    "name": "Strictly validate inputs and activation authority",
                    "id": "preflight",
                    "env": {
                        "INPUT_MODE": "${{ inputs.mode }}",
                        "INPUT_TAG": "${{ inputs.tag }}",
                        "INPUT_TTL_SECONDS": "${{ inputs.ttl_seconds }}",
                        **_IDENTITY_ENV,
                    },
                    "run": _shell(
                        "set -euo pipefail",
                        "python3 tools/controller_preflight.py validate \\",
                        "  --policy config/release-controller-activation.json \\",
                        '  --github-output "$GITHUB_OUTPUT"',
                    ),
                },
                {
                    "name": "Emit non-mutating quarantine receipt",
                    "if": "${{ steps.preflight.outputs.mode == 'dry-run' }}",
                    "env": {
                        "INPUT_MODE": "${{ steps.preflight.outputs.mode }}",
                        "INPUT_TAG": "${{ steps.preflight.outputs.tag }}",
                        "INPUT_TTL_SECONDS": (
                            "${{ steps.preflight.outputs.ttl_seconds }}"
                        ),
                        **_IDENTITY_ENV,
                    },
                    "run": _shell(
                        "set -euo pipefail",
                        "python3 tools/controller_preflight.py receipt \\",
                        "  --policy config/release-controller-activation.json \\",
                        "  > controller-quarantine-receipt.json",
                    ),
                },
                {
                    "name": "Upload quarantine receipt",
                    "if": "${{ steps.preflight.outputs.mode == 'dry-run' }}",
                    "uses": UPLOAD_ARTIFACT_ACTION,
                    "with": {
                        "name": "controller-quarantine-receipt",
                        "path": "controller-quarantine-receipt.json",
                        "if-no-files-found": "error",
                        "retention-days": 30,
                    },
                },
            ],
        }
    },
}

EXPECTED_CI_WORKFLOW: dict[str, Any] = {
    "name": "Controller quarantine checks",
    "on": {
        "pull_request": None,
        "push": {"branches": ["master"]},
    },
    "permissions": {},
    "jobs": {
        "contract": {
            "name": (
                "Validate quarantine contract (Python ${{ matrix.python-version }})"
            ),
            "runs-on": "ubuntu-latest",
            "permissions": {"contents": "read"},
            "strategy": {
                "fail-fast": False,
                "matrix": {"python-version": ["3.11", "3.12"]},
            },
            "env": {"UV_PYTHON": "${{ matrix.python-version }}"},
            "steps": [
                {
                    "name": "Checkout controller source",
                    "uses": CHECKOUT_ACTION,
                    "with": {"persist-credentials": False},
                },
                {
                    "name": "Install uv",
                    "uses": SETUP_UV_ACTION,
                    "with": {"version": "0.11.28"},
                },
                {
                    "name": "Set up Python",
                    "uses": SETUP_PYTHON_ACTION,
                    "with": {"python-version": "${{ matrix.python-version }}"},
                },
                {
                    "name": "Synchronize locked validation dependencies",
                    "run": "uv sync --frozen",
                },
                {
                    "name": "Validate source, tests, and module boundaries",
                    "run": _shell(
                        "set -euo pipefail",
                        "uv run --frozen ruff check scripts tests tools",
                        "uv run --frozen ruff format --check scripts tests tools",
                        (
                            "uv run --frozen python -B -m compileall -q "
                            "scripts tests tools"
                        ),
                        ("uv run --frozen python -B -m unittest discover -s tests -v"),
                        (
                            "uv run --frozen python -m json.tool "
                            "config/release-controller-activation.json >/dev/null"
                        ),
                    ),
                },
                {
                    "name": "Verify generated contracts are current",
                    "run": _shell(
                        "set -euo pipefail",
                        "for producer in scripts/generate_*.py; do",
                        '  uv run --frozen python -B "${producer}" --check',
                        "done",
                        (
                            "uv run --frozen python -B -m "
                            "tools.evidence.release_receipt_vectors --check"
                        ),
                    ),
                },
            ],
        },
        "broker": {
            "name": "Validate quarantined broker",
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 30,
            "permissions": {"contents": "read"},
            "defaults": {"run": {"working-directory": "broker"}},
            "env": {
                "CI": "true",
                "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
                "NODE_OPTIONS": "",
                "NODE_PATH": "",
                "WRANGLER_LOG_SANITIZE": "true",
            },
            "steps": [
                {
                    "name": "Checkout controller and broker source",
                    "uses": CHECKOUT_ACTION,
                    "with": {"persist-credentials": False},
                },
                {
                    "name": "Set up the pinned broker Node runtime",
                    "uses": SETUP_NODE_ACTION,
                    "with": {
                        "node-version-file": "broker/.node-version",
                        "package-manager-cache": False,
                    },
                },
                {
                    "name": "Enable the pinned broker package manager",
                    "run": _shell(
                        "set -euo pipefail",
                        "corepack enable",
                        "corepack install --global pnpm@11.19.0",
                        'test "$(node --version)" = "v$(cat .node-version)"',
                        'test "$(pnpm --version)" = "11.19.0"',
                    ),
                },
                {
                    "name": (
                        "Install the frozen broker dependency graph without "
                        "lifecycle scripts"
                    ),
                    "run": "pnpm install --frozen-lockfile --ignore-scripts",
                },
                {
                    "name": "Validate the broker quarantine contract",
                    "run": "pnpm check",
                },
            ],
        },
    },
}

EXPECTED_WORKFLOW_FILENAMES = frozenset(
    {
        "ci.yml",
        "controller-quarantine.yml",
    }
)
