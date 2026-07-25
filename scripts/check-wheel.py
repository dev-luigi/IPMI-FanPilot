"""Assert the built wheel ships static/** + per-module *.sql + the branding version (SC-4).

Run `python -m build` first (writes dist/, gitignored). Then `python scripts/check-wheel.py`.

The expected version is read from backend/core/branding.py (_VERSION_FALLBACK), the single source
of truth, so a version bump needs no edit here.

Gitignore note: dist/ + ipmideck.egg-info/ are gitignored build artifacts — never `git add` them.
"""
from __future__ import annotations

import glob
import pathlib
import re
import sys
import zipfile

_branding = pathlib.Path(__file__).resolve().parent.parent / "backend" / "core" / "branding.py"
_match = re.search(r'_VERSION_FALLBACK\s*=\s*"([^"]+)"', _branding.read_text(encoding="utf-8"))
if not _match:
    sys.exit("could not read _VERSION_FALLBACK from backend/core/branding.py")
VERSION = _match.group(1)

whls = sorted(glob.glob("dist/ipmideck-*.whl"))
if not whls:
    sys.exit("no wheel in dist/ — run `python -m build` first")
z = zipfile.ZipFile(whls[-1])
n = z.namelist()
assert any(p.startswith("backend/static/") for p in n), "no SPA (backend/static/) in wheel"
assert any(p.endswith(".sql") and "/migrations/" in p for p in n), "no *.sql migrations in wheel"
assert any(
    p == f"ipmideck-{VERSION}.dist-info/METADATA" for p in n
), f"version drift (expected {VERSION})"
print(f"wheel OK: {len(n)} entries")
