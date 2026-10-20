"""Shared pytest fixtures and path setup for the SFTMS test-suite."""

from __future__ import annotations

import os
import sys

# Ensure the sibling `sftms` package is importable when running `pytest` from
# the project root.
_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

import pytest  # noqa: E402


@pytest.fixture()
def sample_tree(tmp_path):
    """Create a small sensitive/normal directory tree for tests."""
    sensitive = tmp_path / "sensitive"
    normal = tmp_path / "normal"
    sensitive.mkdir()
    normal.mkdir()
    (sensitive / "id_rsa.key").write_text("PRIVATE KEY\n", encoding="utf-8")
    (sensitive / "secrets.env").write_text("TOKEN=abc\n", encoding="utf-8")
    (normal / "notes.txt").write_text("hello\n", encoding="utf-8")
    return {"root": tmp_path, "sensitive": sensitive, "normal": normal}
