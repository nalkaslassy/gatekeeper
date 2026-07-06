from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_repo(tmp_path):
    """Copy a named fixture repo under tests/fixtures/<name> into a fresh
    tmp_path so tests can mutate it (write baselines, edit lockfiles) without
    touching the committed fixture or leaking state between tests."""

    def _copy(name: str) -> Path:
        src = FIXTURES_DIR / name
        dst = tmp_path / name
        shutil.copytree(src, dst)
        return dst

    return _copy
