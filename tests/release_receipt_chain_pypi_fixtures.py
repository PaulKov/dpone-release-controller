"""PyPI file fixtures for receipt-v2 streams."""

from __future__ import annotations

import copy
from typing import Any

from tests import release_receipt_publish_fixtures as publish
from tests import release_receipt_fixtures as base


def pypi_file(
    project: str, filename: str, transition: str, verified_count: int
) -> dict[str, Any]:
    payload = copy.deepcopy(publish.pypi(transition, verified_count=verified_count))
    expected = next(
        item
        for item in base._distributions()
        if item["project"] == project and item["filename"] == filename
    )
    file_digest = expected["sha256"]
    payload.update(
        {
            "project": project,
            "filename": filename,
            "size_bytes": expected["size_bytes"],
            "sha256": file_digest,
            "provider_observation_sha256": base.digest(
                f"{project}/{filename}/{transition}"
            ),
        }
    )
    if "integrity" in payload:
        integrity = payload["integrity"]
        integrity["api_path"] = (
            f"/integrity/{project}/{base.VERSION}/{filename}/provenance"
        )
        integrity["file_url"] = (
            f"https://files.pythonhosted.org/packages/aa/bb/{filename}"
        )
        integrity["subject_sha256"] = file_digest
    return payload


PYPI_FILES = (
    (
        "apache-airflow-providers-dpone",
        "apache_airflow_providers_dpone-0.74.0-py3-none-any.whl",
    ),
    ("apache-airflow-providers-dpone", "apache_airflow_providers_dpone-0.74.0.tar.gz"),
    ("dpone", "dpone-0.74.0-py3-none-any.whl"),
    ("dpone", "dpone-0.74.0.tar.gz"),
    ("dpone-airflow-pack", "dpone_airflow_pack-0.74.0-py3-none-any.whl"),
    ("dpone-airflow-pack", "dpone_airflow_pack-0.74.0.tar.gz"),
    ("dpone-native-accel", "dpone_native_accel-0.74.0-py3-none-any.whl"),
    ("dpone-native-accel", "dpone_native_accel-0.74.0.tar.gz"),
)
