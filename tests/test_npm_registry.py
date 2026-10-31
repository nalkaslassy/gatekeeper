from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile

import pytest

from gatekeeper_cli import npm_registry
from gatekeeper_cli.npm_registry import (
    NpmVersionMetadata,
    files_from_npm_tarball,
    inspect_npm_versions,
)


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _tarball(files: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, raw in files.items():
            data = raw.encode() if isinstance(raw, str) else raw
            info = tarfile.TarInfo(f"package/{path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_tarball_parser_strips_package_prefix_and_never_extracts_to_disk():
    data = _tarball({"lib/index.js": "module.exports = 1;\n"})
    files = files_from_npm_tarball(data)
    assert files == {"lib/index.js": b"module.exports = 1;\n"}


def test_tarball_parser_rejects_path_traversal():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        raw = b"oops"
        info = tarfile.TarInfo("../escape.js")
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    with pytest.raises(ValueError, match="unsafe archive path"):
        files_from_npm_tarball(buf.getvalue())


def test_inspect_npm_versions_verifies_integrity_and_detects_colors_pattern(monkeypatch):
    good = _tarball({
        "lib/index.js": "module.exports = require('./colors');\n",
    })
    bad = _tarball({
        "lib/index.js": (
            "module.exports = require('./colors');\n"
            "for (let i = 666; i < Infinity; i++) { console.log(i); }\n"
        ),
    })

    metadata = {
        "https://registry.npmjs.org/colors/1.4.0": {
            "name": "colors",
            "version": "1.4.0",
            "dist": {
                "tarball": "https://registry.npmjs.org/colors/-/colors-1.4.0.tgz",
                "integrity": _integrity(good),
            },
        },
        "https://registry.npmjs.org/colors/1.4.1": {
            "name": "colors",
            "version": "1.4.1",
            "dist": {
                "tarball": "https://registry.npmjs.org/colors/-/colors-1.4.1.tgz",
                "integrity": _integrity(bad),
            },
        },
    }
    payloads = {
        **{url: json.dumps(doc).encode() for url, doc in metadata.items()},
        "https://registry.npmjs.org/colors/-/colors-1.4.0.tgz": good,
        "https://registry.npmjs.org/colors/-/colors-1.4.1.tgz": bad,
    }

    def fake_open(url, *, timeout):
        assert timeout > 0
        return _Response(payloads[url])

    monkeypatch.setattr(npm_registry, "_open", fake_open)
    result = inspect_npm_versions("colors", "1.4.0", "1.4.1")
    rules = {e["rule"] for e in result["diff"]["risk_events"]}
    assert "content-infinite-loop" in rules
    assert result["candidate"]["package"]["verified_with"] == "sha512"


def test_integrity_failure_stops_analysis(monkeypatch):
    tarball = _tarball({"index.js": "module.exports = 1;"})
    metadata = json.dumps({
        "name": "x",
        "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            "integrity": "sha512-" + base64.b64encode(b"wrong").decode(),
        },
    }).encode()
    payloads = {
        "https://registry.npmjs.org/x/1.0.0": metadata,
        "https://registry.npmjs.org/x/-/x-1.0.0.tgz": tarball,
    }

    monkeypatch.setattr(
        npm_registry, "_open", lambda url, *, timeout: _Response(payloads[url])
    )
    with pytest.raises(ValueError, match="integrity verification failed"):
        npm_registry.fetch_npm_content_snapshot("x", "1.0.0")


def test_scoped_package_metadata_url_is_encoded(monkeypatch):
    seen: list[str] = []
    tarball = _tarball({"index.js": "module.exports = 1;"})
    doc = {
        "name": "@scope/pkg",
        "version": "1.0.0",
        "dist": {
            "tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
            "integrity": _integrity(tarball),
        },
    }

    def fake_open(url, *, timeout):
        seen.append(url)
        if url.endswith("/@scope%2Fpkg/1.0.0"):
            return _Response(json.dumps(doc).encode())
        return _Response(tarball)

    monkeypatch.setattr(npm_registry, "_open", fake_open)
    npm_registry.fetch_npm_content_snapshot("@scope/pkg", "1.0.0")
    assert seen[0].endswith("/@scope%2Fpkg/1.0.0")
