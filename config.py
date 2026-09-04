# config.py
from pathlib import Path
import sys

# ---------------------------------------------------------------------
# Project Directories
# ---------------------------------------------------------------------

BASE_DIR     = Path(__file__).resolve().parent

TARGETS_DIR  = BASE_DIR / "targets"
SBOMS_DIR    = BASE_DIR / "sboms"
DEPTREES_DIR = BASE_DIR / "deptrees"
GRAPHS_DIR   = BASE_DIR / "graphs"
RESULTS_DIR  = BASE_DIR / "results"
LOGS_DIR     = BASE_DIR / "logs"
DB_PATH      = BASE_DIR / "cve_cache" / "transrisk.db"
PROJECT_LIST = BASE_DIR / "project_list.csv"

# ---------------------------------------------------------------------
# Platform-aware paths
# Windows venvs use Scripts/, Linux/Mac use bin/
# ---------------------------------------------------------------------

IS_WINDOWS = sys.platform == "win32"
VENV_BIN   = "Scripts" if IS_WINDOWS else "bin"
PIP_EXE    = "pip.exe"    if IS_WINDOWS else "pip"
PYTHON_EXE = "python.exe" if IS_WINDOWS else "python"

# The tools venv = whatever is currently running these scripts
TOOLS_PYTHON = Path(sys.executable)

# ---------------------------------------------------------------------
# Analysis tools to exclude from dependency graphs
# These must never appear as nodes in research artifacts
# ---------------------------------------------------------------------

TOOL_PACKAGES = {
    "pipdeptree", "cyclonedx-bom", "cyclonedx_bom",
    "pip-audit", "pip_audit", "pip", "setuptools",
    "wheel", "pkg-resources", "pkg_resources"
}

# ---------------------------------------------------------------------
# NVD API Key — get free key from https://nvd.nist.gov/developers/request-an-api-key
# ---------------------------------------------------------------------

NVD_API_KEY = "your-nvd-api-key-here"   # replace this

# ---------------------------------------------------------------------
# TransRisk Algorithm Parameters
# ---------------------------------------------------------------------

ALPHA_VALUES   = [0.7, 0.8, 0.9]   # decay factors for sensitivity analysis
DEFAULT_ALPHA  = 0.8

# ---------------------------------------------------------------------
# Create all required directories on import
# ---------------------------------------------------------------------

for _dir in [TARGETS_DIR, SBOMS_DIR, DEPTREES_DIR,
             GRAPHS_DIR, RESULTS_DIR, LOGS_DIR, DB_PATH.parent]:
    _dir.mkdir(parents=True, exist_ok=True)