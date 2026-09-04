# 03_generate_deptrees.py

import csv
import json
import logging
import os
import subprocess
from pathlib import Path

from config import (
    TARGETS_DIR,
    DEPTREES_DIR,
    PROJECT_LIST,
    LOGS_DIR,
    VENV_BIN,
    PYTHON_EXE,
    TOOL_PACKAGES,
)

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGS_DIR.mkdir(parents=True, exist_ok=True)
DEPTREES_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(
            str(LOGS_DIR / "03_generate_deptrees.log"), encoding="utf-8"
        ),
        logging.StreamHandler(),
    ],
)

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def get_env_python(env_path: Path) -> Path:
    return env_path / VENV_BIN / PYTHON_EXE


def target_subprocess_env() -> dict[str, str]:
    """Prevent the active tools venv from affecting a target venv command."""
    env = os.environ.copy()
    for variable in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH", "__PYVENV_LAUNCHER__"):
        env.pop(variable, None)
    return env


def validate_tree(tree: list, package_name: str) -> bool:
    """
    Tree is valid if:
    - It is a non-empty list
    - At least one entry matches the target package name (case-insensitive)
    - That entry has a dependencies key
    """
    if not tree or not isinstance(tree, list):
        return False

    normalized = package_name.lower().replace("-", "_")
    for entry in tree:
        entry_name = entry.get("package_name", "").lower().replace("-", "_")
        if entry_name == normalized:
            return True

    return False


def find_root_entry(tree: list, package_name: str) -> dict | None:
    """
    Find the target package's entry in the raw pipdeptree output.
    Handles case differences (Django vs django) and hyphen/underscore variants.
    """
    normalized = package_name.lower().replace("-", "_")

    # Pass 1 — exact normalized match
    for entry in tree:
        entry_name = entry.get("package_name", "").lower().replace("-", "_")
        if entry_name == normalized:
            return entry

    # Pass 2 — fallback: exclude known tool packages, take first remaining
    logging.warning(
        f"[WARN] '{package_name}' not found as root in tree. "
        f"Available roots: {[e.get('package_name') for e in tree]}"
    )
    return None


# ---------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------

def generate_deptree(package_name: str) -> bool:
    env_path    = TARGETS_DIR / f"{package_name}_env"
    output_path = DEPTREES_DIR / f"{package_name}_tree.json"

    # Pre-flight
    if not env_path.exists():
        logging.error(f"[SKIP] {package_name} — environment not found, run 01 first")
        return False

    target_python = get_env_python(env_path)
    if not target_python.exists():
        logging.error(f"[SKIP] {package_name} — Python not found at {target_python}")
        return False

    # Skip only if existing file is valid
    if output_path.exists():
        try:
            with open(output_path, encoding="utf-8") as f:
                existing = json.load(f)
            if validate_tree(existing, package_name):
                dep_count = len(existing[0].get("dependencies", []))
                logging.info(
                    f"[SKIP] {package_name} — valid tree exists "
                    f"({dep_count} direct deps)"
                )
                return True
            else:
                logging.warning(
                    f"[REGEN] {package_name} — existing tree invalid or empty, "
                    f"regenerating"
                )
                output_path.unlink()
        except (json.JSONDecodeError, IndexError):
            logging.warning(f"[REGEN] {package_name} — corrupt tree file, regenerating")
            output_path.unlink()

    logging.info(f"[TREE] Generating dependency tree for {package_name}")

    pip_exe = env_path / VENV_BIN / "pip.exe" if VENV_BIN == "Scripts" else \
              env_path / VENV_BIN / "pip"

    # Step 1 — install pipdeptree into target env
    install_result = subprocess.run(
        [str(target_python), "-I", "-m", "pip", "install", "pipdeptree", "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=target_subprocess_env(),
    )

    if install_result.returncode != 0:
        logging.error(
            f"[FAIL] {package_name} — could not install pipdeptree: "
            f"{(install_result.stderr or '').strip()}"
        )
        return False

    # Step 2 — run pipdeptree
    run_result = subprocess.run(
        [str(target_python), "-I", "-m", "pipdeptree", "--json-tree"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=target_subprocess_env(),
    )

    # Step 3 — always uninstall pipdeptree regardless of outcome
    subprocess.run(
        [str(target_python), "-I", "-m", "pip", "uninstall", "pipdeptree", "-y", "--quiet"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=target_subprocess_env(),
    )

    # Step 4 — handle pipdeptree output
    if run_result.returncode != 0:
        logging.error(f"[FAIL] {package_name} — pipdeptree failed")
        if (run_result.stderr or "").strip():
            logging.error(f"  stderr: {(run_result.stderr or '').strip()}")
        return False

    if not (run_result.stdout or "").strip():
        logging.error(
            f"[FAIL] {package_name} — pipdeptree returned empty output. "
            f"Package may not have installed correctly."
        )
        return False

    try:
        full_tree = json.loads(run_result.stdout or "")
    except json.JSONDecodeError as e:
        logging.error(f"[FAIL] {package_name} — invalid JSON from pipdeptree: {e}")
        return False

    if not full_tree:
        logging.error(
            f"[FAIL] {package_name} — pipdeptree returned empty list. "
            f"Check that the package installed correctly in {env_path}"
        )
        return False

    # Step 5 — extract only the target package's subtree
    root_entry = find_root_entry(full_tree, package_name)

    if root_entry is None:
        logging.error(
            f"[FAIL] {package_name} — could not find package root in tree. "
            f"All roots: {[e.get('package_name') for e in full_tree]}"
        )
        return False

    # Save as single-element list for consistency with build_graphs.py
    target_tree = [root_entry]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(target_tree, f, indent=2)

    dep_count = len(root_entry.get("dependencies", []))
    logging.info(
        f"[DONE] {package_name} — {dep_count} direct deps -> {output_path.name}"
    )

    return True


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    with open(PROJECT_LIST, newline="", encoding="utf-8") as f:
        packages = [row["project_name"].strip() for row in csv.DictReader(f)]

    logging.info(f"Generating dependency trees for {len(packages)} packages")

    success, failed, failed_list = 0, 0, []

    for package in packages:
        if generate_deptree(package):
            success += 1
        else:
            failed += 1
            failed_list.append(package)

    logging.info("=" * 60)
    logging.info(f"Trees Generated : {success}")
    logging.info(f"Failures        : {failed}")
    if failed_list:
        logging.warning(f"Failed packages : {failed_list}")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()
