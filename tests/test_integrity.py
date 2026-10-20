"""Tests for :mod:`sftms.integrity`."""

from __future__ import annotations

from sftms.db import Database
from sftms.integrity import IntegrityManager


def _manager(tmp_path, sensitive):
    db = Database(str(tmp_path / "test.db"))
    return IntegrityManager(db, algorithm="sha256", alerts=None, protected_dirs=[str(sensitive)])


def test_baseline_and_verify_intact(tmp_path, sample_tree):
    manager = _manager(tmp_path, sample_tree["sensitive"])
    summary = manager.create_baseline(str(sample_tree["sensitive"]))
    assert summary["files"] == 2

    result = manager.verify()
    assert len(result.intact) == 2
    assert not result.modified
    assert not result.deleted


def test_modified_file_detected(tmp_path, sample_tree):
    manager = _manager(tmp_path, sample_tree["sensitive"])
    manager.create_baseline(str(sample_tree["sensitive"]))

    target = sample_tree["sensitive"] / "secrets.env"
    target.write_text("TOKEN=changed\n", encoding="utf-8")

    result = manager.verify()
    assert str(target) in result.modified


def test_deleted_file_detected(tmp_path, sample_tree):
    manager = _manager(tmp_path, sample_tree["sensitive"])
    manager.create_baseline(str(sample_tree["sensitive"]))
    (sample_tree["sensitive"] / "id_rsa.key").unlink()

    result = manager.verify()
    assert any(p.endswith("id_rsa.key") for p in result.deleted)


def test_added_file_detected(tmp_path, sample_tree):
    manager = _manager(tmp_path, sample_tree["sensitive"])
    manager.create_baseline(str(sample_tree["sensitive"]))
    (sample_tree["sensitive"] / "new_contract.pdf").write_text("x", encoding="utf-8")

    result = manager.verify()
    assert any(p.endswith("new_contract.pdf") for p in result.added)


def test_check_modification_reports_change(tmp_path, sample_tree):
    manager = _manager(tmp_path, sample_tree["sensitive"])
    manager.create_baseline(str(sample_tree["sensitive"]))
    target = sample_tree["sensitive"] / "secrets.env"

    # Unchanged -> None.
    assert manager.check_modification(str(target)) is None

    target.write_text("TOKEN=tampered\n", encoding="utf-8")
    new_hash = manager.check_modification(str(target))
    assert new_hash is not None

    # Non-baselined file -> None.
    other = sample_tree["normal"] / "notes.txt"
    assert manager.check_modification(str(other)) is None
