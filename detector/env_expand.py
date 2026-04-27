"""Replace ${ENV_VAR} in YAML-loaded strings using os.environ."""

from __future__ import annotations

import os
import re
from typing import Any

_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env_placeholders(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: expand_env_placeholders(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_env_placeholders(x) for x in obj]
    if isinstance(obj, str):
        return _PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), obj)
    return obj
