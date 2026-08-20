"""Adversarial tests for bounded actual broker-record hash semantics."""

from __future__ import annotations

import hashlib
import json
import unittest
from unittest import mock

from tools.evidence import release_broker_record_envelope as record


class BrokerRecordEnvelopeTests(unittest.TestCase):
    def test_record_id_and_full_record_digest_use_the_actual_broker_algorithm(
        self,
    ) -> None:
        body = {
            "schema": "dpone.release-broker-provisioned.v1",
            "schema_version": 1,
            "sequence": 0,
        }
        encoded = record.encode_record(body)
        verified = record.verify_record_bytes(encoded)

        self.assertEqual(verified.document["record_id"], verified.record_id)
        self.assertEqual(
            verified.record_sha256,
            "sha256:" + hashlib.sha256(encoded).hexdigest(),
        )
        self.assertNotEqual(verified.record_id, verified.record_sha256)

        changed = dict(verified.document)
        changed["record_id"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            record.BrokerRecordEnvelopeError, "record_id mismatch"
        ):
            record.verify_record_bytes(_canonical(changed))

    def test_exact_byte_boundary_accepts_65536_and_rejects_65537(self) -> None:
        empty = record.encode_record(_body_with_padding(""))
        accepted = record.encode_record(
            _body_with_padding("x" * (record.MAX_BROKER_RECORD_BYTES - len(empty)))
        )
        self.assertEqual(len(accepted), record.MAX_BROKER_RECORD_BYTES)
        self.assertEqual(record.verify_record_bytes(accepted).canonical_bytes, accepted)

        oversized = _record_bytes_for_size(record.MAX_BROKER_RECORD_BYTES + 1)
        self.assertEqual(len(oversized), record.MAX_BROKER_RECORD_BYTES + 1)
        with mock.patch.object(
            record.json,
            "loads",
            side_effect=AssertionError("JSON parser must not be called"),
        ):
            with self.assertRaisesRegex(
                record.BrokerRecordEnvelopeError, "1..65536 bytes"
            ):
                record.verify_record_bytes(oversized)

    def test_noncanonical_duplicate_and_prefilled_id_inputs_fail_closed(self) -> None:
        body = _body_with_padding("")
        with self.assertRaisesRegex(record.BrokerRecordEnvelopeError, "must omit"):
            record.derive_record_id({**body, "record_id": "sha256:" + "0" * 64})

        encoded = record.encode_record(body)
        with self.assertRaisesRegex(record.BrokerRecordEnvelopeError, "not canonical"):
            record.verify_record_bytes(encoded.replace(b":", b": ", 1))

        duplicate = encoded[:-1] + b',"schema_version":1}'
        with self.assertRaisesRegex(record.BrokerRecordEnvelopeError, "duplicate"):
            record.verify_record_bytes(duplicate)


def _body_with_padding(padding: str) -> dict[str, object]:
    return {
        "padding": padding,
        "schema": "dpone.release-broker-provisioned.v1",
        "schema_version": 1,
        "sequence": 0,
    }


def _record_bytes_for_size(size: int) -> bytes:
    empty = record.encode_record(_body_with_padding(""))
    body = _body_with_padding("x" * (size - len(empty)))
    document = dict(body)
    document["record_id"] = record.derive_record_id(body)
    encoded = _canonical(document)
    if len(encoded) != size:
        raise AssertionError("fixture did not reach the requested exact byte size")
    return encoded


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
