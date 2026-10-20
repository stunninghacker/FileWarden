"""Tests for :mod:`sftms.authorizer`."""

from __future__ import annotations

from sftms.alerts import HIGH, LOW
from sftms.authorizer import Authorizer, Decision
from sftms.classifier import Classifier
from sftms.db import Event


def _authorizer(threshold=50, window=60):
    clf = Classifier(sensitive_dirs=[], sensitive_patterns=["*.key", "*secret*"])
    return Authorizer(
        clf,
        cloud_patterns=["*dropbox*"],
        removable_patterns=["*usb*"],
        network_patterns=["*smb*"],
        bulk_threshold=threshold,
        bulk_window_seconds=window,
    )


def test_sensitive_local_raises_low(tmp_path):
    auth = _authorizer()
    event = Event(event_type="modified", src_path=str(tmp_path / "id_rsa.key"))
    results = auth.evaluate(event)

    assert len(results) == 1
    assert results[0].decision is Decision.SENSITIVE_LOCAL
    assert results[0].severity == LOW
    assert event.is_sensitive is True


def test_sensitive_to_usb_raises_high(tmp_path):
    auth = _authorizer()
    dest = tmp_path / "usb_drive" / "id_rsa.key"
    event = Event(event_type="moved", src_path=str(tmp_path / "id_rsa.key"), dest_path=str(dest))
    results = auth.evaluate(event)

    severities = [r.severity for r in results]
    assert HIGH in severities
    assert event.dest_class == "removable"


def test_sensitive_to_cloud_raises_high(tmp_path):
    auth = _authorizer()
    dest = tmp_path / "Dropbox" / "secrets.conf"
    event = Event(event_type="created", src_path=str(dest), dest_path=str(dest))
    results = auth.evaluate(event)

    assert any(r.severity == HIGH and r.dest_class.value == "cloud" for r in results)


def test_network_destination_detected(tmp_path):
    auth = _authorizer()
    dest = tmp_path / "smb_share" / "team_secret.txt"
    event = Event(event_type="created", src_path=str(dest), dest_path=str(dest))
    results = auth.evaluate(event)

    assert event.dest_class == "network"
    assert any(r.severity == HIGH and r.dest_class.value == "network" for r in results)


def test_non_sensitive_local_is_silent(tmp_path):
    auth = _authorizer()
    event = Event(event_type="created", src_path=str(tmp_path / "notes.txt"))
    assert auth.evaluate(event) == []
    assert event.is_sensitive is False


def test_bulk_exfiltration_triggers_critical(tmp_path):
    auth = _authorizer(threshold=3, window=60)
    usb = tmp_path / "usb_drive"
    decisions = []
    for i in range(3):
        dest = usb / f"file_{i}.txt"
        event = Event(event_type="created", src_path=str(dest), dest_path=str(dest))
        decisions.extend(r.decision for r in auth.evaluate(event))

    assert Decision.BULK_EXFILTRATION in decisions


def test_bulk_counter_resets_after_reset(tmp_path):
    auth = _authorizer(threshold=3, window=60)
    usb = tmp_path / "usb_drive"
    for i in range(2):
        dest = usb / f"f{i}.txt"
        auth.evaluate(Event(event_type="created", src_path=str(dest), dest_path=str(dest)))
    auth.reset()
    dest = usb / "f3.txt"
    results = auth.evaluate(Event(event_type="created", src_path=str(dest), dest_path=str(dest)))
    assert all(r.decision is not Decision.BULK_EXFILTRATION for r in results)
