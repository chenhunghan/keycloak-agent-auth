"""Entrypoint when the resource server runs as a standalone service
(inside docker compose, alongside Keycloak).
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict

from .resource_server import ResourceServer


def _greet(args: Dict[str, Any]) -> Dict[str, Any]:
    raw = args.get("name")
    name = raw if isinstance(raw, str) else "world"
    return {"greeting": f"Hello, {name}!"}


def main() -> None:
    port = int(os.environ.get("PORT", "3000"))
    try:
        rs = ResourceServer.start_on(port, {"/exec/greet": _greet})
    except Exception as exc:  # noqa: BLE001
        print(f"[rs-standalone] fatal: {exc}", file=sys.stderr)
        sys.exit(1)
    print("[rs-standalone] ready", flush=True)
    rs.serve_forever()


if __name__ == "__main__":
    main()
