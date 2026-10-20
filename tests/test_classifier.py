"""Tests for :mod:`sftms.classifier`."""

from __future__ import annotations

from sftms.classifier import Classifier


def test_file_under_sensitive_dir_is_sensitive(sample_tree):
    clf = Classifier(sensitive_dirs=[str(sample_tree["sensitive"])], sensitive_patterns=[])
    assert clf.is_sensitive(str(sample_tree["sensitive"] / "anything.bin")) is True


def test_normal_file_is_not_sensitive(sample_tree):
    clf = Classifier(sensitive_dirs=[str(sample_tree["sensitive"])], sensitive_patterns=[])
    assert clf.is_sensitive(str(sample_tree["normal"] / "notes.txt")) is False


def test_pattern_match_is_case_insensitive(sample_tree):
    clf = Classifier(sensitive_dirs=[], sensitive_patterns=["*.KEY", "*secret*"])
    assert clf.is_sensitive(str(sample_tree["sensitive"] / "id_rsa.KEY")) is True
    assert clf.is_sensitive(str(sample_tree["root"] / "MySecrets.txt")) is True


def test_match_reports_rule(sample_tree):
    clf = Classifier(
        sensitive_dirs=[str(sample_tree["sensitive"])], sensitive_patterns=["payroll*"]
    )
    kind, rule = clf.match(str(sample_tree["sensitive"] / "id_rsa.key"))
    assert kind == "directory"

    kind, rule = clf.match(str(sample_tree["normal"] / "payroll_2024.xlsx"))
    assert kind == "pattern"


def test_none_and_empty_paths(sample_tree):
    clf = Classifier(sensitive_dirs=[str(sample_tree["sensitive"])], sensitive_patterns=["*.key"])
    assert clf.is_sensitive(None) is False
    assert clf.is_sensitive("") is False
