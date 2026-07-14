"""Load scenario specifications from YAML with strict validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import ScenarioSpec
from .resources import packaged_path

MAX_DOCUMENT_BYTES = 1_048_576


def _read_yaml(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{path} exceeds {MAX_DOCUMENT_BYTES} bytes")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a top-level mapping")
    return data


def load_scenarios(path: Path) -> tuple[ScenarioSpec, ...]:
    document = _read_yaml(path)
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("document must contain a 'scenarios' list")
    return tuple(ScenarioSpec.model_validate(entry) for entry in scenarios)


def load_default_scenarios() -> tuple[ScenarioSpec, ...]:
    return load_scenarios(packaged_path("scenarios.yaml"))
