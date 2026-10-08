"""Create the deliberately mismatched VAmPI spec used by the exercise."""
import sys
from pathlib import Path

import yaml

REMOVE = ("/users/v1/_debug", "/createdb")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: python scripts/make_edited_spec.py INPUT OUTPUT")

    source, destination = map(Path, sys.argv[1:3])
    spec = yaml.safe_load(source.read_text(encoding="utf-8"))
    for path in REMOVE:
        spec.get("paths", {}).pop(path, None)

    spec["paths"]["/users/v1"]["get"]["deprecated"] = True
    spec["servers"] = [{"url": "http://127.0.0.1:18080"}]

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(spec, sort_keys=False),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
