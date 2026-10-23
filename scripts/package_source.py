#!/usr/bin/env python3
"""Create a portable GitHub project download, excluding local Site identity and secrets."""
from pathlib import Path
import os
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'dist' / 'cyberwatch.zip'
ROOT_FILES = {'README.md', 'package.json', '.gitignore', '.python-version', 'requirements.txt', 'Dockerfile', '.dockerignore', 'render.yaml'}
DIRECTORIES = ('dist', 'data', 'scripts', 'server', 'tests', '.github')
ALLOWED_SUFFIXES = {'.html', '.css', '.js', '.mjs', '.json', '.svg', '.png', '.py', '.yml', '.yaml', '.md'}


def package():
    files = [ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()]
    for directory in DIRECTORIES:
        for path in (ROOT / directory).rglob('*'):
            if path.is_symlink() or not path.is_file() or path.suffix not in ALLOWED_SUFFIXES:
                continue
            if any(part in {'__pycache__', 'node_modules', '.git', '.openai'} for part in path.relative_to(ROOT).parts):
                continue
            if path.name.startswith(('qa-', '.env')):
                continue
            files.append(path)
    temporary = OUTPUT.with_suffix('.zip.tmp')
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(files):
                archive.write(path, path.relative_to(ROOT).as_posix())
        os.replace(temporary, OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)
    print(f'Portable project ready: {OUTPUT.name} ({len(files)} files; {OUTPUT.stat().st_size:,} bytes)')


if __name__ == '__main__':
    package()
