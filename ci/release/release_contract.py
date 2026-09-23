"""Backend release schema; deliberately distinct from frontend/ops deployment schema."""
import re
from oci import require
REPOSITORY = 'LUMII-AILab/clarin-dspace'
IMAGE = 'ghcr.io/lumii-ailab/clarin-dspace'
WORKFLOW = '.github/workflows/clarin-release.yml'


def validate(record):
    require(record.get('schema') == 1 and record.get('component') == 'backend', 'Invalid backend schema')
    require(record.get('repository') == REPOSITORY and record.get('image') == IMAGE, 'Wrong publisher')
    require(re.fullmatch(r'[a-f0-9]{40}', record.get('source', '')), 'Invalid source commit')
    for key in ('digest', 'config_digest'):
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', record.get(key, '')), 'Invalid ' + key)
    require(record.get('version') == 'sha-' + record['source'], 'Version/source mismatch')
    require(record.get('local') is False, 'Local review candidate is not publishable')
    require(record.get('workflow') == WORKFLOW and type(record.get('run_id')) is int
            and record['run_id'] > 0, 'Invalid workflow identity')
    require(record.get('checks') == {'oci': 'passed', 'authentication': 'passed', 'artifact': 'passed'},
            'Incomplete qualification')
    require(record.get('production_accepted') is False, 'Production acceptance is outside this procedure')
    require(record.get('scan_policy') == 'synthetic-report-v1', 'Unexpected scan policy')
    return record
