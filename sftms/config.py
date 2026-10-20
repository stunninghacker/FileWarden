"""Configuration loading and validation for SFTMS.

Reads a YAML configuration file, applies sensible defaults, validates the
values and exposes a strongly-typed :class:`Config` object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

DEFAULT_CONFIG_NAME = "config.yaml"

VALID_HASH_ALGORITHMS = ("sha256", "md5")


class ConfigError(ValueError):
    """Raised when the configuration file is missing or invalid."""


def _expand(path: str) -> str:
    """Expand ``~`` and environment variables and return an absolute path."""
    return os.path.abspath(os.path.expandvars(os.path.expanduser(str(path))))


def _as_list(value: Any, name: str) -> List[str]:
    """Coerce a config value into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    raise ConfigError(f"'{name}' must be a string or a list of strings")


@dataclass
class Config:
    """Validated SFTMS configuration.

    Attributes mirror the keys documented in ``config.yaml``. Directories are
    stored expanded to absolute paths; the pattern lists are left verbatim so
    they can be matched case-insensitively by the classifier.
    """

    watch_dirs: List[str] = field(default_factory=list)
    sensitive_dirs: List[str] = field(default_factory=list)
    sensitive_patterns: List[str] = field(default_factory=list)
    cloud_folder_patterns: List[str] = field(default_factory=list)
    removable_path_patterns: List[str] = field(default_factory=list)
    network_path_patterns: List[str] = field(default_factory=list)
    ignore_patterns: List[str] = field(default_factory=list)
    hash_algorithm: str = "sha256"
    bulk_threshold: int = 50
    bulk_window_seconds: int = 60
    db_path: str = "~/sftms/sftms.db"
    log_dir: str = "~/sftms/logs"
    report_dir: str = "~/sftms/reports"
    enable_desktop_notifications: bool = False
    enable_process_attribution: bool = False
    #: Directory the config was loaded from (used to resolve relative paths).
    base_dir: str = field(default="", repr=False)

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, data: Dict[str, Any], base_dir: str = "") -> "Config":
        """Build a :class:`Config` from a raw mapping, applying defaults."""
        if not isinstance(data, dict):
            raise ConfigError("Configuration root must be a mapping")
        base_dir = base_dir or os.getcwd()

        def resolve_dir(value: Any, name: str) -> str:
            raw = _expand(value) if value is not None else ""
            if not raw:
                raise ConfigError(f"'{name}' must not be empty")
            if not os.path.isabs(raw):
                raw = os.path.abspath(os.path.join(base_dir, raw))
            return raw

        def list_of(key: str) -> List[str]:
            return _as_list(data.get(key), key)

        def dir_list(key: str) -> List[str]:
            return [resolve_dir(v, key) for v in list_of(key)]

        cfg = cls(
            watch_dirs=dir_list("watch_dirs"),
            sensitive_dirs=dir_list("sensitive_dirs"),
            sensitive_patterns=list_of("sensitive_patterns"),
            cloud_folder_patterns=list_of("cloud_folder_patterns"),
            removable_path_patterns=list_of("removable_path_patterns"),
            network_path_patterns=list_of("network_path_patterns"),
            ignore_patterns=list_of("ignore_patterns"),
            hash_algorithm=str(data.get("hash_algorithm", "sha256")).lower(),
            bulk_threshold=int(data.get("bulk_threshold", 50)),
            bulk_window_seconds=int(data.get("bulk_window_seconds", 60)),
            db_path=_expand(data.get("db_path", "~/sftms/sftms.db")),
            log_dir=_expand(data.get("log_dir", "~/sftms/logs")),
            report_dir=_expand(data.get("report_dir", "~/sftms/reports")),
            enable_desktop_notifications=bool(data.get("enable_desktop_notifications", False)),
            enable_process_attribution=bool(data.get("enable_process_attribution", False)),
            base_dir=base_dir,
        )
        cfg.validate()
        return cfg

    # ------------------------------------------------------------------ #
    # Validation / helpers
    # ------------------------------------------------------------------ #
    def validate(self) -> None:
        """Validate required values; raise :class:`ConfigError` on failure."""
        if not self.watch_dirs:
            raise ConfigError("At least one 'watch_dirs' entry is required")
        if self.hash_algorithm not in VALID_HASH_ALGORITHMS:
            raise ConfigError(
                f"'hash_algorithm' must be one of {VALID_HASH_ALGORITHMS}, "
                f"got {self.hash_algorithm!r}"
            )
        if self.bulk_threshold < 1:
            raise ConfigError("'bulk_threshold' must be >= 1")
        if self.bulk_window_seconds < 1:
            raise ConfigError("'bulk_window_seconds' must be >= 1")

    def ensure_runtime_dirs(self) -> None:
        """Create the database, log and report directories if needed."""
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.report_dir).mkdir(parents=True, exist_ok=True)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    @property
    def alerts_log_path(self) -> str:
        """Absolute path of the append-only alert log."""
        return os.path.join(self.log_dir, "alerts.log")

    def all_patterns(self) -> Iterable[str]:
        """Yield every pattern the classifier should consider."""
        yield from self.sensitive_patterns


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load and validate a YAML config file.

    Parameters
    ----------
    path:
        Path to the YAML file. When omitted, ``./config.yaml`` is used.
    """
    if path is None:
        path = DEFAULT_CONFIG_NAME
    path = _expand(path if path else DEFAULT_CONFIG_NAME)
    if not os.path.isfile(path):
        raise ConfigError(f"Configuration file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - defensive
            raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    return Config.from_dict(data, base_dir=os.path.dirname(path))
