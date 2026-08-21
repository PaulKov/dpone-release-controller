"""Privacy canary for schemas and generated artifacts safe to publish."""

from __future__ import annotations

import base64
import binascii
import hashlib
from io import BytesIO
import json
import re
import unittest
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from tests.release_service_authority_fixtures import ACCOUNT_ID

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_GENERATED_ROOTS = (ROOT / "docs/schemas", ROOT / "tests/fixtures")
SYNTHETIC_ACCOUNT_ID = "0" * 32
SYNTHETIC_REQUEST_ID = "request-01HXDPONE"
SYNTHETIC_CLOUDFLARE_UUID_RE = re.compile(r"00000000-0000-4000-8000-[0-9a-f]{12}\Z")
CLOUDFLARE_IDENTITY_RE = re.compile(
    r"cloudflare-worker:(?P<account>[^/\s]+)/(?P<worker>[^@\s]+)@"
    r"(?P<version>[^\s]+)\Z"
)
CANDIDATE_READER_VERSION_ALLOWLIST = frozenset({"candidate-reader-version-01"})
ALLOWED_NON_UUID_VERSIONS_BY_KEY = {
    "candidate_reader_service_version_id": CANDIDATE_READER_VERSION_ALLOWLIST,
    "x-dpone-candidate-reader-service-version-id": CANDIDATE_READER_VERSION_ALLOWLIST,
    "worker_version_id": frozenset({"worker-version-001"}),
}
CANDIDATE_READER_IDENTITY_ALLOWLIST = frozenset(
    {
        "cloudflare-worker:account-01/"
        "dpone-release-candidate-reader@candidate-reader-version-01"
    }
)
ALLOWED_NON_UUID_IDENTITIES_BY_KEY = {
    "candidate_reader_service_identity": CANDIDATE_READER_IDENTITY_ALLOWLIST,
    "x-dpone-candidate-reader-service-identity": CANDIDATE_READER_IDENTITY_ALLOWLIST,
}
ALLOWED_NON_UUID_DEPLOYMENTS_BY_KEY: Mapping[str, frozenset[str]] = {}

# These names and identifiers belonged to the retired raw-ledger projection.
# Exact tokens avoid blocking unrelated assets such as the held runtime action.
FORBIDDEN_PUBLIC_CLOSURE_TOKENS = frozenset(
    token.encode()
    for token in (
        "dpone.release-controller-closed-finalize-response.v1",
        "dpone.release-controller-closure-manifest.v1",
        "dpone.release-controller-closure-materialization.v1",
        "dpone.release-controller-closure-upload-proof.v1",
        "dpone.release-controller-runtime-closure-verification-result.v1",
        "dpone.release-evidence.v2",
        "dpone.release-runtime-closure-provider-observation.v1",
        "dpone.release-runtime-closure-request.v1",
        "dpone.release-runtime-closure-stream-response.v1",
        "release-controller-closure-v1",
        "closed-receipt-v2.json",
        "closure-manifest-v1.json",
        "receipt-chain-v2.json",
        "release-controller-closure-manifest-v1.schema.json",
        "release-evidence-v2.json",
        "release-evidence-v2.schema.json",
        "release-runtime-closure-provider-observation-v1.schema.json",
        "release-runtime-closure-request-v1.schema.json",
        "release-runtime-closure-stream-response-v1.schema.json",
    )
)

MAX_BASE64_ENCODED_BYTES = 32 * 1024 * 1024
MAX_BASE64_DECODED_BYTES = 32 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ENCODING_DEPTH = 2
BASE64_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9+/_-])"
    rb"([A-Za-z0-9+/_-][A-Za-z0-9+/_ \t\r\n]{14,}[A-Za-z0-9+/_-]={0,2})"
    rb"(?![A-Za-z0-9+/_=-])"
)


def _artifact_payloads() -> Iterator[tuple[str, bytes]]:
    """Yield containers, ZIP member names, and decompressed member bytes."""

    for root in PUBLIC_GENERATED_ROOTS:
        paths = sorted(
            candidate for candidate in root.rglob("*") if candidate.is_file()
        )
        for path in paths:
            location = path.relative_to(ROOT).as_posix()
            payload = path.read_bytes()
            yield location, payload
            if path.suffix.lower() != ".zip":
                continue
            yield from _zip_member_payloads(location, payload)


def _zip_member_payloads(location: str, payload: bytes) -> Iterator[tuple[str, bytes]]:
    """Read bounded ZIP members in memory without filesystem extraction."""

    with ZipFile(BytesIO(payload)) as archive:
        for member in sorted(archive.infolist(), key=lambda item: item.filename):
            member_location = f"{location}!/{member.filename}"
            yield f"{member_location}#name", member.filename.encode("utf-8")
            if member.is_dir():
                continue
            if member.file_size > MAX_ZIP_MEMBER_BYTES:
                raise ValueError(f"oversized public ZIP member: {member_location}")
            yield member_location, archive.read(member)


def _expanded_payloads(location: str, payload: bytes) -> Iterator[tuple[str, bytes]]:
    """Yield raw, JSON-string, and recursively decoded base64 layers."""

    pending = [(location, payload, 0)]
    seen: set[bytes] = set()
    while pending:
        current_location, current, depth = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        yield current_location, current
        if depth >= MAX_ENCODING_DEPTH:
            continue

        document = _load_json(current)
        if document is not None:
            for json_path, value in _json_strings(document):
                pending.append(
                    (f"{current_location} JSON {json_path}", value.encode(), depth + 1)
                )
        for encoding, decoded in _base64_decodings(current):
            pending.append(
                (f"{current_location} {encoding}-base64", decoded, depth + 1)
            )


def _public_content_layers() -> Iterator[tuple[str, bytes]]:
    for location, payload in _artifact_payloads():
        yield from _expanded_payloads(location, payload)


def _forbidden_occurrences(
    payloads: Iterator[tuple[str, bytes]], forbidden: frozenset[bytes]
) -> Iterator[tuple[str, bytes]]:
    for location, payload in payloads:
        for expanded_location, expanded in _expanded_payloads(location, payload):
            for token in forbidden:
                if token in expanded:
                    yield expanded_location, token


def _load_json(payload: bytes) -> Any | None:
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _json_strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield f"{path}.<key>", key
            yield from _json_strings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _json_strings(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _json_fields(value: Any, path: str = "$") -> Iterator[tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, key, child
            yield from _json_fields(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _json_fields(child, f"{path}[{index}]")


def _base64_decodings(payload: bytes) -> Iterator[tuple[str, bytes]]:
    """Decode bounded standard/base64url tokens, including MIME whitespace."""

    decoded_values: set[bytes] = set()
    encoded_total = 0
    decoded_total = 0
    for match in BASE64_TOKEN_RE.finditer(payload):
        encoded = match.group(1)
        encoded_total += len(encoded)
        if encoded_total > MAX_BASE64_ENCODED_BYTES:
            raise ValueError("public artifact exceeds the base64 scan budget")
        token = encoded.translate(None, b" \t\r\n")
        if len(token) < 16:
            continue
        padded = token + b"=" * (-len(token) % 4)
        for name, altchars in (("standard", None), ("urlsafe", b"-_")):
            try:
                decoded = base64.b64decode(
                    padded,
                    altchars=altchars,
                    validate=True,
                )
            except (binascii.Error, ValueError):
                continue
            if decoded and decoded not in decoded_values:
                decoded_total += len(decoded)
                if decoded_total > MAX_BASE64_DECODED_BYTES:
                    raise ValueError("public artifact exceeds the decoded scan budget")
                decoded_values.add(decoded)
                yield name, decoded


def _legacy_account_material() -> frozenset[bytes]:
    """Build every banned form without checking in the legacy token itself."""

    account = _legacy_account()
    digest = hashlib.sha256(account).hexdigest().encode()
    direct = (account, digest, b"sha256:" + digest)
    encoded: set[bytes] = set()
    for value in direct:
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            representation = encoder(value)
            encoded.update((representation, representation.rstrip(b"=")))
    return frozenset((*direct, *encoded))


def _legacy_account() -> bytes:
    return "".join(("2b3a32ac", "b9d30739", "d5c08166", "2dfe0797")).encode()


def _normalized_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def _is_version_key(key: str) -> bool:
    key = _normalized_key(key)
    return (
        key == "worker_version_id"
        or key.endswith("_worker_version_id")
        or key == "service_version_id"
        or key.endswith("_service_version_id")
    )


def _is_deployment_key(key: str) -> bool:
    key = _normalized_key(key)
    return key == "deployment_id" or key.endswith("_deployment_id")


def _is_account_identifier_key(key: str) -> bool:
    parts = _normalized_key(key).split("_")
    return "account" in parts and parts[-1] in {
        "account",
        "digest",
        "id",
        "identifier",
        "sha256",
    }


def _is_storage_identifier_key(key: str) -> bool:
    parts = _normalized_key(key).split("_")
    namespace = {"b2", "bucket", "storage", "store"}
    identifiers = namespace.union(
        {"id", "identifier", "key", "name", "uri", "url", "version"}
    )
    return any(part in namespace for part in parts) and parts[-1] in identifiers


class PublicGeneratedArtifactPrivacyTests(unittest.TestCase):
    def test_forbidden_material_is_absent_at_every_encoding_layer(self) -> None:
        forbidden_sets = (
            ("legacy account", _legacy_account_material()),
            ("retired closure", FORBIDDEN_PUBLIC_CLOSURE_TOKENS),
        )
        for category, forbidden in forbidden_sets:
            with self.subTest(category=category):
                hits = tuple(_forbidden_occurrences(_artifact_payloads(), forbidden))
                self.assertEqual(hits, ())

    def test_scanner_exposes_zip_and_base64_hidden_legacy_material(self) -> None:
        digest = hashlib.sha256(_legacy_account()).hexdigest().encode()
        buffer = BytesIO()
        with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("nested/private.json", b'{"digest":"' + digest + b'"}')
        zipped = buffer.getvalue()
        self.assertNotIn(digest, zipped)

        hits = tuple(
            _forbidden_occurrences(
                _zip_member_payloads("probe.zip", zipped),
                _legacy_account_material(),
            )
        )
        self.assertTrue(any("private.json" in location for location, _ in hits))

        document = b'{"account_id":"' + _legacy_account() + b'"}'
        encoded = base64.urlsafe_b64encode(document).rstrip(b"=")
        json_string = json.dumps(encoded.decode()).encode()
        hits = tuple(
            _forbidden_occurrences(
                iter((("probe.json", json_string),)),
                _legacy_account_material(),
            )
        )
        self.assertTrue(any(token == _legacy_account() for _, token in hits))

        mime = b"\r\n".join(
            encoded[index : index + 12] for index in range(0, len(encoded), 12)
        )
        hits = tuple(
            _forbidden_occurrences(
                iter((("probe.mime", mime),)), _legacy_account_material()
            )
        )
        self.assertTrue(any(token == _legacy_account() for _, token in hits))

    def test_provider_identifier_key_aliases_fail_closed(self) -> None:
        account_keys = "provider_account_id cloudflare-account-id provider.account.id"
        for key in account_keys.split():
            with self.subTest(account_key=key):
                self.assertTrue(_is_account_identifier_key(key))
        storage_keys = "provider_storage_identifier store_id provider/store/identifier"
        for key in storage_keys.split():
            with self.subTest(storage_key=key):
                self.assertTrue(_is_storage_identifier_key(key))

    def test_cloudflare_namespaces_are_explicitly_synthetic(self) -> None:
        self.assertEqual(ACCOUNT_ID, SYNTHETIC_ACCOUNT_ID)
        counts = dict.fromkeys(
            ("account", "deployment", "identity", "request", "version"), 0
        )
        for location, payload in _public_content_layers():
            document = _load_json(payload)
            if document is None:
                continue
            for json_path, key, value in _json_fields(document):
                context = f"{location} JSON {json_path}"
                if _is_storage_identifier_key(key):
                    self.fail(f"provider storage identifier requires review: {context}")
                if not isinstance(value, str):
                    continue
                if _is_account_identifier_key(key):
                    counts["account"] += 1
                    self.assertEqual(value, SYNTHETIC_ACCOUNT_ID, context)
                if _normalized_key(key).endswith("request_id"):
                    counts["request"] += 1
                    self.assertEqual(value, SYNTHETIC_REQUEST_ID, context)
                if _is_deployment_key(key):
                    counts["deployment"] += 1
                    self._assert_synthetic_uuid(
                        value,
                        ALLOWED_NON_UUID_DEPLOYMENTS_BY_KEY.get(key, ()),
                        context,
                    )
                if _is_version_key(key):
                    counts["version"] += 1
                    self._assert_synthetic_uuid(
                        value,
                        ALLOWED_NON_UUID_VERSIONS_BY_KEY.get(key, ()),
                        context,
                    )
                if "cloudflare-worker:" in value:
                    counts["identity"] += 1
                    allowed = ALLOWED_NON_UUID_IDENTITIES_BY_KEY.get(key, ())
                    if value in allowed:
                        continue
                    match = CLOUDFLARE_IDENTITY_RE.fullmatch(value)
                    if match is None:
                        self.fail(f"malformed Cloudflare identity at {context}")
                    self.assertEqual(
                        match.group("account"), SYNTHETIC_ACCOUNT_ID, context
                    )
                    self.assertRegex(
                        match.group("version"), SYNTHETIC_CLOUDFLARE_UUID_RE, context
                    )

        for namespace, count in counts.items():
            with self.subTest(namespace=namespace):
                self.assertGreaterEqual(count, 2)

    def _assert_synthetic_uuid(
        self,
        value: str,
        allowed: frozenset[str] | tuple[()],
        context: str,
    ) -> None:
        if value not in allowed:
            self.assertRegex(value, SYNTHETIC_CLOUDFLARE_UUID_RE, context)


if __name__ == "__main__":
    unittest.main()
