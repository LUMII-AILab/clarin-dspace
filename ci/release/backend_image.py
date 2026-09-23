#!/usr/bin/env python3
"""Prepare an explicit source snapshot; verify exact OCI candidates. Never publish."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
from oci import inspect_archive, require

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / 'ci/release/image'


def toolchain():
    data = json.loads((RECIPE / 'toolchain.json').read_text())
    for key in ('maven_image', 'runtime_image', 'buildkit_image', 'sbom_generator', 'skopeo_image'):
        require(re.fullmatch(r'[a-z0-9./-]+@sha256:[0-9a-f]{64}', data[key]), 'Unpinned ' + key)
    require(data['image'] == 'ghcr.io/lumii-ailab/clarin-dspace', 'Unexpected publisher')
    require(data['platform'] == 'linux/amd64', 'Unsupported platform')
    return data


def git(*args, root=ROOT):
    return subprocess.check_output(['git', *args], cwd=root)


def prepare(destination, evidence, local=False, root=ROOT):
    require(not destination.exists(), 'Source destination already exists')
    status = git('status', '--porcelain', '--untracked-files=all', root=root)
    require(local or not status, 'Release builds require a clean checkout; use --local for unpublished review')
    revision = git('rev-parse', 'HEAD', root=root).decode().strip()
    epoch = int(git('show', '-s', '--format=%ct', 'HEAD', root=root))
    paths = git('ls-files', '-z', '--cached', '--others', '--exclude-standard', root=root).split(b'\0')
    submodules = {line.split(b'\t', 1)[1] for line in git('ls-files', '--stage', root=root).splitlines()
                  if line.startswith(b'160000 ')}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for raw in sorted(set(paths) - submodules - {b''}):
            relative = Path(os.fsdecode(raw))
            require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe source path')
            if any(part in ('.git', '.dspace-skills', 'target') for part in relative.parts):
                continue
            path = root / relative
            if not path.exists() and not path.is_symlink():
                continue  # Deliberately deleted file in a local review snapshot.
            require(path.is_file() and not path.is_symlink(), 'Source must contain regular files: ' + str(relative))
            data = path.read_bytes()
            entry = tarfile.TarInfo(relative.as_posix())
            entry.size, entry.mtime = len(data), epoch
            entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            archive.addfile(entry, io.BytesIO(data))
    payload = stream.getvalue()
    source_hash = hashlib.sha256(payload).hexdigest()
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        archive.extractall(destination, filter='data')
    data = toolchain() | dict(source_commit=revision, source_revision=revision,
        source_tree=git('rev-parse', 'HEAD^{tree}', root=root).decode().strip(),
        source_archive_sha256=source_hash, source_date_epoch=str(epoch), local=local)
    if local:
        data['source_revision'] += '-local-' + source_hash[:12]
    data['tag'] = 'sha-' + data['source_revision']
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / 'inputs.json').write_text(json.dumps(data, indent=2) + '\n')
    (evidence / 'source.tar').write_bytes(payload)
    for key, value in data.items():
        if isinstance(value, str):
            require('\n' not in value and '\r' not in value, 'Unsafe workflow output')
            print(f'{key}={value}')
    print(f'context={destination.resolve()}')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('destination', type=Path)
    p.add_argument('evidence', type=Path)
    p.add_argument('--local', action='store_true')
    p = sub.add_parser('inspect')
    p.add_argument('archive', type=Path)
    p.add_argument('digest')
    p.add_argument('evidence', type=Path)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.destination, args.evidence, args.local)
    else:
        print(json.dumps(inspect_archive(args.archive, args.digest, args.evidence)))


if __name__ == '__main__':
    main()
