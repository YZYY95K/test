"""Build the reproducible AgentTeams Worker package."""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    template = root / "agentteams" / "worker-package"
    skills = root / "skills"
    output = root / "dist" / "devflow-worker.zip"
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="devflow-package-") as temp_dir:
        staging = Path(temp_dir) / "package"
        shutil.copytree(template, staging)
        shutil.copytree(skills, staging / "skills")
        manifest_path = staging / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["source"]["created_at"] = datetime.now(timezone.utc).isoformat()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(staging).as_posix())

    print(output)


if __name__ == "__main__":
    main()

