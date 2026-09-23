#!/usr/bin/env python3
"""Fail closed before credentials can publish a retained candidate; never rebuild."""
import json
import os
from pathlib import Path
from backend_image import git
from oci import inspect_archive, require
from release_contract import validate
from record import create


def verify(root=Path('output')):
    evidence = root / 'evidence'
    record = validate(json.loads((evidence / 'release.json').read_text()))
    require(record['source'] == git('rev-parse', 'HEAD').decode().strip(), 'Checkout/source mismatch')
    require(record['digest'] == os.environ['EXPECTED_DIGEST'], 'Job digest mismatch')
    require(record['run_id'] == int(os.environ['GITHUB_RUN_ID']), 'Run identity mismatch')
    require(record == create(evidence), 'Candidate reports changed')
    identity = inspect_archive(root / 'backend.oci.tar', record['digest'], evidence)
    require(identity['config_digest'] == record['config_digest'], 'Image config mismatch')
    return record


if __name__ == '__main__':
    verify()
