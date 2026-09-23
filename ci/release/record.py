#!/usr/bin/env python3
"""Create digest-bound candidate evidence after artifact, authentication and scan gates."""
import hashlib
import json
import os
from pathlib import Path
from backend_image import toolchain
from oci import require
from qualify import EXPECTED
from release_contract import REPOSITORY, IMAGE, WORKFLOW, validate

REPORTS = ('inputs.json', 'identity.json', 'qualification.json', 'vulnerabilities.json',
           'jars.sha256', 'maven-version.txt', 'trivy-database.json')


def create(root=Path('output/evidence')):
    data = json.loads((root / 'inputs.json').read_text())
    require(all(data[k] == v for k, v in toolchain().items()), 'Build recipe changed')
    require(hashlib.sha256((root / 'source.tar').read_bytes()).hexdigest() == data['source_archive_sha256'],
            'Source archive differs')
    if not data['local']:
        require(data['source_revision'] == data['source_commit'], 'Release source is not a commit')
    identity = json.loads((root / 'identity.json').read_text())
    qualification = json.loads((root / 'qualification.json').read_text())
    require(identity['source_revision'] == data['source_revision'], 'OCI source mismatch')
    require(qualification['source_revision'] == identity['source_revision']
            and qualification['config_digest'] == identity['config_digest']
            and qualification['result'] == 'passed', 'Qualification mismatch')
    suites = qualification['authentication_tests']
    require(suites.keys() == EXPECTED.keys() and all(suites[k] >= v for k, v in EXPECTED.items()),
            'Authentication qualification incomplete')
    scan = json.loads((root / 'vulnerabilities.json').read_text())
    require(scan.get('SchemaVersion') == 2 and 'Results' in scan, 'Invalid scan report')
    policy = json.loads(Path('ci/release/scan-policy.json').read_text())
    require(policy['id'] == 'synthetic-report-v1' and policy['findings'] == 'report-only'
            and policy['scanner_errors'] == 'fail' and policy['production_accepted'] is False
            and policy['exceptions'] == [], 'Scan policy changed')
    result = dict(schema=1, component='backend', repository=REPOSITORY, image=IMAGE,
                  source=data['source_commit'], version=data['tag'], local=data['local'],
                  digest=identity['index_digest'], config_digest=identity['config_digest'],
                  source_archive_sha256=data['source_archive_sha256'],
                  runtime_base=data['runtime_image'], builder=data['maven_image'],
                  workflow=WORKFLOW, run_id=int(os.environ.get('GITHUB_RUN_ID', '0')),
                  checks=dict(oci='passed', authentication='passed', artifact='passed'),
                  scan_policy='synthetic-report-v1', production_accepted=False,
                  reports={name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in REPORTS})
    if not data['local']:
        validate(result)
    return result


if __name__ == '__main__':
    record = create()
    Path('output/evidence/release.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
