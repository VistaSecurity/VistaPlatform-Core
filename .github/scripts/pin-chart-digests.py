#!/usr/bin/env python3
"""Pin image digests into charts/vistaplatform/values.yaml at release time.

Reads digest fragments produced by the build-images job (one JSON file per
image with {name, image, digest}) and rewrites values.yaml so each backend,
frontend, and gateway entry has an `image.digest` set. The chart's image
helper prefers digest over tag when both are present.

Usage:
    pin-chart-digests.py --values charts/vistaplatform/values.yaml --digests digests/

The script preserves YAML structure and comments via ruamel.yaml.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from ruamel.yaml import YAML
except ImportError:
    print(
        "ruamel.yaml is required. Install with: pip install ruamel.yaml",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--digests", required=True, type=Path)
    args = parser.parse_args()

    if not args.values.exists():
        print(f"values file not found: {args.values}", file=sys.stderr)
        return 1
    if not args.digests.is_dir():
        print(f"digests dir not found: {args.digests}", file=sys.stderr)
        return 1

    digests: dict[str, str] = {}
    for f in args.digests.glob("*.json"):
        try:
            with f.open() as fp:
                data = json.load(fp)
            digests[data["name"]] = data["digest"]
        except (json.JSONDecodeError, KeyError) as e:
            print(f"skipping malformed digest fragment {f}: {e}", file=sys.stderr)

    if not digests:
        print("no digests collected — refusing to rewrite values.yaml", file=sys.stderr)
        return 1

    print(f"Pinning {len(digests)} digests:")
    for k, v in sorted(digests.items()):
        print(f"  {k}: {v}")

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    with args.values.open() as fp:
        values = yaml.load(fp)

    # Backends — every entry in the map.
    backends = values.get("backends", {})
    for name in backends:
        if name in digests:
            entry = backends[name]
            if "image" not in entry:
                entry["image"] = {}
            entry["image"]["digest"] = digests[name]
        else:
            print(f"WARNING: no digest for backend {name}", file=sys.stderr)

    # Frontends.
    if "frontend" in values:
        for ui_key, image_name in [("webUi", "web-ui"), ("adminUi", "admin-ui")]:
            if image_name in digests and ui_key in values["frontend"]:
                entry = values["frontend"][ui_key]
                if "image" not in entry:
                    entry["image"] = {}
                entry["image"]["digest"] = digests[image_name]

    # Note: gateway uses upstream traefik image, not pinned by this pipeline.

    with args.values.open("w") as fp:
        yaml.dump(values, fp)

    print(f"Updated {args.values}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
