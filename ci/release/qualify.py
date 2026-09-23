#!/usr/bin/env python3
"""Check exact loaded artifact and embedded Maven reports without live services."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from oci import require

EXPECTED = {'ClarinExistingAccountTest': 5, 'ShibGroupLoggingTest': 2,
            'ClarinReturnUrlTest': 2, 'ClarinShibbolethLoginFilterIT': 7,
            'ClarinShibbolethAuthAssing2GroupsIT': 3}


def reports(root):
    suites = {}
    for path in root.rglob('TEST-*.xml'):
        suite = ET.parse(path).getroot()
        name = suite.attrib['name'].rsplit('.', 1)[-1]
        require(name not in suites, 'Duplicate test suite')
        require(all(int(suite.get(key, '0')) == 0 for key in ('failures', 'errors', 'skipped')),
                'Failed or skipped authentication tests')
        cases = suite.findall('testcase')
        require(len(cases) == int(suite.attrib['tests']), 'Test count mismatch')
        require(all(not list(case) or all(c.tag in ('system-out', 'system-err') for c in case)
                    for case in cases), 'Failed, skipped or retried authentication case')
        suites[name] = len(cases)
    require(suites.keys() == EXPECTED.keys(), 'Missing/unexpected authentication suites')
    require(all(suites[k] >= v for k, v in EXPECTED.items()), 'Missing authentication cases')
    return suites


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def qualify(evidence):
    identity = json.loads((evidence / 'identity.json').read_text())
    image = identity['config_digest']
    config = json.loads(run('docker', 'image', 'inspect', image))[0]
    require(config['Id'] == image, 'Loaded artifact differs')
    require(config['Config']['Labels']['org.opencontainers.image.revision'] == identity['source_revision'],
            'Loaded source differs')
    inputs = json.loads((evidence / 'inputs.json').read_text())
    expected_scope = 'authentication-local-only' if inputs['local'] else 'backend-candidate'
    require(config['Config']['Labels']['lv.clarin.qualification'] == expected_scope,
            'Wrong local/release qualification scope')
    require(config['Config']['Labels']['lv.clarin.source.archive.sha256'] == inputs['source_archive_sha256'],
            'Loaded source snapshot differs')
    # No network, host mounts, persistent volume or database initialization.
    run('docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--entrypoint=sh', image, '-ec',
        'test "$(id -u)" = 1100; test -x /dspace/bin/dspace; '
        'test -f /dspace/config/dspace.cfg; '
        'test -d /dspace/assetstore; test -f /dspace/webapps/server/WEB-INF/lib/dspace-api-7.6.5.jar; '
        'grep -qx "dspace.dir=/dspace" /dspace/webapps/server/WEB-INF/classes/application.properties; '
        'cd /dspace; sha256sum --check --status /usr/share/clarin-build/jars.sha256; java -version')
    container = run('docker', 'create', '--network=none', '--entrypoint=true', image)
    try:
        with tempfile.TemporaryDirectory() as directory:
            run('docker', 'cp', container + ':/usr/share/clarin-build/.', directory)
            suites = reports(Path(directory))
            for name in ('jars.sha256', 'maven-version.txt'):
                (evidence / name).write_bytes((Path(directory) / name).read_bytes())
    finally:
        run('docker', 'rm', '-v', container)
    result = dict(result='passed', config_digest=image, source_revision=identity['source_revision'],
                  authentication_tests=suites, scope='artifact-integrity-and-authentication-tests')
    (evidence / 'qualification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    qualify(parser.parse_args().evidence)
