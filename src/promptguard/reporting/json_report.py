"""JSON report writer.

Serialises a ``RedteamReport`` to a JSON file. The schema is defined by
``RedteamReport.model_dump(mode='json')`` — keep it stable across versions.
"""

from __future__ import annotations

import json
from pathlib import Path

from promptguard.models import RedteamReport


def write_json_report(report: RedteamReport, path: Path) -> Path:
    """Write ``report`` to ``path`` as pretty-printed JSON.

    Args:
        report: The populated red-team report.
        path: Output path. Parent directory will be created if missing.

    Returns:
        The path that was written (for chaining).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
