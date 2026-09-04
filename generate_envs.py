# 01_generate_envs.py

import subprocess
import csv
import logging
from pathlib import Path
from config import TARGETS_DIR, PROJECT_LIST, VENV_BIN, PYTHON_EXE, PIP_EXE, LOGS_DIR

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------

LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(str(LOGS_DIR / "01_generate_envs.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def get_env_python(env_path: Path) -> Path:
    return env_path / VENV_BIN / PYTHON_EXE

def get_env_pip(env_path: Path) -> Path:
    return env_path / VENV_BIN / PIP_EXE

def get_installed_version(python_exe: Path, package_name: str) -> str:
    """
    Returns the exact installed version of the package using pip show.
    Written to installed_version.txt for use by enrich_cves.py OSV queries.
    """
    result = subprocess.run(
        [str(python_exe), "-m", "pip", "show", package_name],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    for line in (result.stdout or "").splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return ""

# -------------------------------------------------------------------
# Core
# -------------------------------------------------------------------

def create_target_env(package_name: str, pin_version: str = "") -> Path | None:
    """
    Creates an isolated virtual environment for package_name.
    Installs pin_version if specified, otherwise installs latest.
    Writes installed version to installed_version.txt for downstream use.
    Skips creation if env and version file already exist.
    """
    env_path     = TARGETS_DIR / f"{package_name}_env"
    version_file = env_path / "installed_version.txt"

    # Skip if already built
    if env_path.exists() and version_file.exists():
        existing_version = version_file.read_text(encoding="utf-8").strip()
        logging.info(
            f"[SKIP] {package_name} — already exists (v{existing_version})"
        )
        return env_path

    install_target = f"{package_name}=={pin_version}" if pin_version else package_name
    logging.info(f"[CREATE] {package_name} — installing {install_target}")

    # Create clean virtual environment
    try:
        subprocess.run(
            ["python", "-m", "venv", str(env_path)],
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Failed to create venv for {package_name}: {e}")
        return None

    python_exe = get_env_python(env_path)

    if not python_exe.exists():
        logging.error(f"[ERROR] Python not found at {python_exe}")
        return None

    # Upgrade pip silently
    subprocess.run(
        [str(python_exe), "-m", "pip", "install", "--upgrade", "pip"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Install ONLY the target package at pinned version — nothing else
    result = subprocess.run(
        [str(python_exe), "-m", "pip", "install", install_target, "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )

    if result.returncode != 0:
        logging.error(f"[FAIL] Could not install {install_target}")
        logging.error((result.stderr or "").strip())
        # Clean up broken env so next run retries
        import shutil
        shutil.rmtree(env_path, ignore_errors=True)
        return None

    # Capture and store exact installed version
    version = get_installed_version(python_exe, package_name)

    if version:
        version_file.write_text(version, encoding="utf-8")
        logging.info(f"[DONE] {package_name} v{version}")
    else:
        logging.warning(
            f"[WARN] {package_name} installed but version could not be detected"
        )
        version_file.write_text("unknown", encoding="utf-8")

    return env_path


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    TARGETS_DIR.mkdir(parents=True, exist_ok=True)

    with open(PROJECT_LIST, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    # Read project_name and optional pin_version from CSV
    packages = [
        (
            row["project_name"].strip(),
            row.get("pin_version", "").strip()
        )
        for row in rows
    ]

    logging.info(f"Processing {len(packages)} packages")

    success, failed = [], []

    for package_name, pin_version in packages:
        env = create_target_env(package_name, pin_version)
        if env:
            success.append(package_name)
        else:
            failed.append(package_name)

    logging.info("=" * 60)
    logging.info(f"Successful : {len(success)}")
    logging.info(f"Failed     : {len(failed)}")
    if failed:
        logging.warning(f"Failed     : {failed}")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()
