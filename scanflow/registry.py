"""Approved-version registry.

Only configurations that pass the offline audit may be registered.  Registration is
transactional: a rejected configuration leaves every already-approved version
untouched, so an old version can never start reading differently just because a
new document was refused.

Version identity is authoritative: a second document with an existing version is
never allowed to overwrite the approved one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .audit import AuditReport, audit
from .config import CodeConfig, ConfigError


class RegistryError(Exception):
    pass


class VersionConflict(RegistryError):
    """The same version string was offered with different content."""


class ConfigRejected(RegistryError):
    """The configuration failed its offline release audit."""

    def __init__(self, report: AuditReport):
        super().__init__(
            f"version {report.version!r} rejected: "
            f"{len(report.conflicts)} release conflict(s)"
        )
        self.report = report


@dataclass
class _Entry:
    config: CodeConfig
    report: AuditReport
    fingerprint: str


class Registry:
    def __init__(self, *, max_witnesses: int = 8,
                 max_product_states: Optional[int] = None) -> None:
        self._entries: Dict[str, _Entry] = {}
        self._by_wire: Dict[int, str] = {}
        self._max_witnesses = max_witnesses
        self._max_product_states = max_product_states
        self.rejections: List[dict] = []

    # -- registration -------------------------------------------------------

    def register(self, config: CodeConfig) -> AuditReport:
        """Audit and atomically add *config*.

        If an identical configuration is already approved for this version, this
        is an idempotent no-op.  Any different document for the same version raises
        :class:`VersionConflict`; the existing bytes are never replaced.
        """
        fingerprint = _fingerprint(config)
        existing = self._entries.get(config.version)
        if existing is not None:
            if existing.fingerprint == fingerprint:
                return existing.report
            raise VersionConflict(
                f"version {config.version!r} is already approved with different "
                f"content; refusing to overwrite"
            )
        if config.wire is not None:
            owner = self._by_wire.get(config.wire)
            if owner is not None:
                raise VersionConflict(
                    f"wire version {config.wire} is already bound to approved "
                    f"configuration {owner!r}; refusing to overwrite"
                )

        report = audit(config, max_witnesses=self._max_witnesses,
                       max_product_states=self._max_product_states)

        if not report.ok:
            self.rejections.append(report.to_json())
            raise ConfigRejected(report)

        # Commit only after a clean audit.
        self._entries[config.version] = _Entry(config, report, fingerprint)
        if config.wire is not None:
            self._by_wire[config.wire] = config.version
        return report

    def register_json(self, text: str) -> AuditReport:
        return self.register(CodeConfig.from_json_text(text))

    # -- lookup -------------------------------------------------------------

    def get(self, version: str) -> Optional[CodeConfig]:
        entry = self._entries.get(version)
        return None if entry is None else entry.config

    def get_wire(self, wire: int) -> Optional[CodeConfig]:
        version = self._by_wire.get(wire)
        if version is None:
            return None
        return self._entries[version].config

    def __contains__(self, version: str) -> bool:
        return version in self._entries

    def versions(self) -> List[str]:
        return sorted(self._entries)

    def configs(self) -> List[CodeConfig]:
        return [self._entries[v].config for v in self.versions()]

    def reports(self) -> List[AuditReport]:
        return [self._entries[v].report for v in self.versions()]


def _fingerprint(config: CodeConfig) -> str:
    import hashlib
    import json

    canonical = {
        "version": config.version,
        "wire": config.wire,
        "codes": {name: code.hex() for name, code in sorted(config.codes.items())},
        "start": config.start,
        "accepts": sorted(config.accepts),
        "transitions": sorted([s, a, d] for (s, a), d in config.transitions.items()),
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def load_registry(paths: Iterable[Path], *,
                  max_witnesses: int = 8,
                  max_product_states: Optional[int] = None) -> Registry:
    """Build a registry from JSON config files, deterministically ordered.

    Files are processed in sorted path order.  A rejected document is recorded in
    ``registry.rejections`` and skipped; it never alters an already-approved
    version.  Duplicate versions with different content raise.
    """
    registry = Registry(max_witnesses=max_witnesses,
                        max_product_states=max_product_states)
    for path in sorted(Path(p) for p in paths):
        try:
            config = CodeConfig.from_json_text(path.read_text(encoding="utf-8"))
        except (ConfigError, OSError) as exc:
            registry.rejections.append(
                {"version": None, "source": str(path), "ok": False,
                 "error": f"{type(exc).__name__}: {exc}"}
            )
            continue
        try:
            registry.register(config)
        except ConfigRejected as exc:
            entry = exc.report.to_json()
            entry["source"] = str(path)
            registry.rejections.append(entry)
    return registry


def load_registry_dir(directory: Path, **kwargs) -> Registry:
    return load_registry(Path(directory).glob("*.json"), **kwargs)
