#!/usr/bin/env python3
"""Build/qualify an explicitly unpublishable working-tree snapshot; no runtime deployment."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from backend_image import ROOT, prepare
from oci import inspect_archive, require
from qualify import qualify


def run(*args):
    subprocess.run(args, check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='new directory outside the source checkout')
    parser.add_argument('--scan', action='store_true', help='also scan and write a local-only candidate record')
    parser.add_argument('--builder', required=True, help='explicit Buildx docker-container builder')
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists() and ROOT not in output.parents, 'Use a new directory outside the checkout')
    os.umask(0o022)  # public synthetic source must be readable by BuildKit
    output.mkdir(parents=True)
    evidence = output/'evidence'
    with tempfile.TemporaryDirectory(prefix='clarin-backend-source-') as directory:
        source = Path(directory)/'source'
        data = prepare(source, evidence, local=True)
        command = ['docker', 'buildx', 'build', '--builder', args.builder, '--platform', data['platform'],
                   '--file', str(source/'ci/release/image/Dockerfile'), '--provenance=mode=max',
                   '--attest=type=sbom,generator='+data['sbom_generator'],
                   '--output', 'type=oci,dest='+str(output/'backend.oci.tar'),
                   '--metadata-file', str(output/'build-metadata.json'), '--tag', data['image']+':'+data['tag']]
        for key in ('maven_image', 'runtime_image', 'source_revision', 'source_archive_sha256', 'source_date_epoch'):
            command += ['--build-arg', key.upper()+'='+data[key]]
        command += ['--build-arg', 'QUALIFICATION_SCOPE=authentication-local-only']
        run(*command, str(source))
    digest = json.loads((output/'build-metadata.json').read_text())['containerimage.digest']
    inspect_archive(output/'backend.oci.tar', digest, evidence)
    run('docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}', '-v', str(output)+':/artifact',
        data['skopeo_image'], 'copy', '--override-os', 'linux', '--override-arch', 'amd64',
        'oci-archive:/artifact/backend.oci.tar', 'docker-archive:/artifact/runtime.tar:clarin-backend:review')
    run('docker', 'load', '--input', str(output/'runtime.tar'))
    (output/'runtime.tar').unlink()
    qualify(evidence)
    if args.scan:
        from record import create
        run('bash', 'ci/release/scan.sh', str(output/'backend.oci.tar'), str(evidence))
        (evidence/'release.json').write_text(json.dumps(create(evidence), indent=2)+'\n')
    print('Unpublished local candidate:', output)


if __name__ == '__main__': main()
