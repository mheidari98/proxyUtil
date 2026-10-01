"""Smoke tests: every CLI exposes --version and --help and returns exit 0."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from proxyUtil import __version__

CLI_NAMES = [
    "cdnGen",
    "dnsChecker",
    "cfRecorder",
    "ipExtractor",
    "v2rayChecker",
    "clashGen",
    "connectMe",
    "shadowChecker",
    "sslocal2ssURI",
    "ssURI2sslocal",
]


def _resolve(cmd: str) -> str | None:
    """Find a CLI inside the active venv first, then fall back to PATH."""
    venv = Path(sys.executable).parent
    candidate = venv / cmd
    if candidate.exists():
        return str(candidate)
    return shutil.which(cmd)


@pytest.mark.parametrize("name", CLI_NAMES)
def test_cli_version_flag(name):
    path = _resolve(name)
    if path is None:
        pytest.skip(f"{name} not on PATH (package not installed)")
    out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
    assert out.returncode == 0, out.stderr
    combined = (out.stdout + out.stderr).strip()
    assert __version__ in combined, f"{name} --version did not print {__version__}: {combined!r}"


@pytest.mark.parametrize("name", CLI_NAMES)
def test_cli_help_flag(name):
    path = _resolve(name)
    if path is None:
        pytest.skip(f"{name} not on PATH (package not installed)")
    env = {**os.environ, "COLUMNS": "200"}
    out = subprocess.run([path, "--help"], capture_output=True, text=True, timeout=10, env=env)
    assert out.returncode == 0, out.stderr
    assert "usage:" in out.stdout.lower()
