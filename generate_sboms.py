# 02_generate_sboms.py

import csv
import json
import logging
import subprocess
from pathlib import Path

from config import (
    TARGETS_DIR,
    SBOMS_DIR,
    PROJECT_LIST,
    TOOLS_PYTHON,
    LOGS_DIR,
    VENV_BIN,
    PYTHON_EXE,
)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGS_DIR.mkdir(parents=True, exist_ok=True)
SBOMS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(
            str(LOGS_DIR / "02_generate_sboms.log"), encoding="utf-8"
        ),
        logging.StreamHandler(),
    ],
)

# ---------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------

def get_env_python(env_path: Path) -> Path:
    """Return the Python executable inside a target virtual environment."""
    return env_path / VENV_BIN / PYTHON_EXE


def validate_sbom(sbom_path: Path) -> bool:
    """
    Confirms the generated SBOM file:
      - exists and is non-empty
      - is valid JSON
      - contains a 'components' key (CycloneDX structure)
    Returns True only if all checks pass.
    """
    if not sbom_path.exists() or sbom_path.stat().st_size == 0:
        return False
    try:
        with open(sbom_path, encoding="utf-8") as f:
            data = json.load(f)
        return "components" in data
    except (json.JSONDecodeError, KeyError):
        return False


# ---------------------------------------------------------------------
# SBOM Generation
# ---------------------------------------------------------------------

def generate_sbom(package_name: str) -> bool:
    env_path    = TARGETS_DIR / f"{package_name}_env"
    output_path = SBOMS_DIR   / f"{package_name}_sbom.json"

    # Pre-flight checks
    if not env_path.exists():
        logging.error(f"[SKIP] {package_name} — environment not found, run 01 first")
        return False

    target_python = get_env_python(env_path)
    if not target_python.exists():
        logging.error(f"[SKIP] {package_name} — Python not found at {target_python}")
        return False

    if not TOOLS_PYTHON.exists():
        logging.error(f"Tools Python not found: {TOOLS_PYTHON}")
        return False

    # Skip if valid SBOM already exists
    if output_path.exists():
        if validate_sbom(output_path):
            logging.info(f"[SKIP] {package_name} — valid SBOM already exists")
            return True
        else:
            logging.warning(
                f"[REGEN] {package_name} — existing SBOM invalid, regenerating"
            )
            output_path.unlink()

    logging.info(f"[SBOM] Generating for {package_name}")

    # cyclonedx-py analyzes target_python's environment
    # but runs FROM tools venv — zero contamination
    command = [
        str(TOOLS_PYTHON),
        "-m", "cyclonedx_py",
        "environment",
        str(target_python),       # ← analyze THIS env, not the tools env
        "--output-format", "JSON",
        "--output-file", str(output_path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

        if result.returncode != 0:
            logging.error(f"[FAIL] {package_name}")
            if result.stdout.strip():
                logging.error(f"  stdout: {result.stdout.strip()}")
            if result.stderr.strip():
                logging.error(f"  stderr: {result.stderr.strip()}")
            return False

        # Validate before declaring success
        if not validate_sbom(output_path):
            logging.error(
                f"[FAIL] {package_name} — SBOM generated but failed validation"
            )
            return False

        # Log component count for transparency
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
        component_count = len(data.get("components", []))
        logging.info(
            f"[DONE] {package_name} — {component_count} components -> {output_path.name}"
        )
        return True

    except Exception:
        logging.exception(f"Unexpected error processing {package_name}")
        return False


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    with open(PROJECT_LIST, newline="", encoding="utf-8") as f:
        packages = [row["project_name"].strip() for row in csv.DictReader(f)]

    logging.info(f"Generating SBOMs for {len(packages)} packages")

    success, failed = 0, 0
    failed_list = []

    for package in packages:
        if generate_sbom(package):
            success += 1
        else:
            failed += 1
            failed_list.append(package)

    logging.info("=" * 60)
    logging.info(f"SBOMs Generated : {success}")
    logging.info(f"Failures        : {failed}")
    if failed_list:
        logging.warning(f"Failed packages : {failed_list}")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()