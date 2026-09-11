"""
Loads feature flags from settings.yaml using PyYAML.

The usage below is already "correct" (yaml.safe_load, never yaml.load on
untrusted input) — this module is intentionally NOT the vulnerability.
The vulnerability is the outdated PyYAML *version* pinned in requirements.txt
(CVE-2020-14343). This file exists to justify why PyYAML is a real,
used dependency and not just SBOM noise — see docs/VULNERABILITIES.md.
"""

from pathlib import Path
from typing import Any

import yaml

from . import config

_DEFAULTS: dict[str, Any] = {
    "allow_device_search": True,
    "max_devices_per_owner": 500,
    "maintenance_mode": False,
}


def load_feature_flags() -> dict[str, Any]:
    path = Path(config.SETTINGS_FILE)
    if not path.exists():
        return dict(_DEFAULTS)

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    flags = dict(_DEFAULTS)
    flags.update(data)
    return flags
