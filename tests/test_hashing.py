"""Tests for :mod:`sftms.hashing`."""

from __future__ import annotations

import hashlib

import pytest

from sftms.hashing import file_size, hash_bytes, hash_file, hashes_match


def test_hash_file_sha256_matches_hashlib(tmp_path):
    target = tmp_path / "data.bin"
    payload = b"the quick brown fox" * 1000
    target.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert hash_file(str(target), "sha256") == expected


def test_hash_file_md5(tmp_path):
    target = tmp_path / "data.bin"
    payload = b"abc123"
    target.write_bytes(payload)

    assert hash_file(str(target), "md5") == hashlib.md5(payload).hexdigest()


def test_hash_file_missing_returns_none(tmp_path):
    assert hash_file(str(tmp_path / "does_not_exist")) is None


def test_hash_file_chunked_large_file(tmp_path):
    target = tmp_path / "large.bin"
    payload = b"x" * (3 * 1024 * 1024 + 17)  # spans several 1 MiB chunks
    target.write_bytes(payload)

    assert hash_file(str(target), "sha256", chunk_size=1024) == hashlib.sha256(payload).hexdigest()


def test_hash_bytes_matches_file(tmp_path):
    payload = b"consistency-check"
    target = tmp_path / "x.bin"
    target.write_bytes(payload)
    assert hash_bytes(payload) == hash_file(str(target))


def test_invalid_algorithm_raises(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"data")
    with pytest.raises(ValueError):
        hash_file(str(target), "sha512-typo")


def test_file_size_and_hashes_match(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"12345")
    assert file_size(str(target)) == 5

    digest = hash_file(str(target))
    assert hashes_match(str(target), digest) is True
    assert hashes_match(str(target), "deadbeef") is False
    assert hashes_match(str(tmp_path / "missing"), digest) is None
