"""Negative release tests: source omission, skipped tests, OCI corruption and permissions."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
import backend_image as m
from oci import inspect_archive
from qualify import EXPECTED, reports
from release_contract import validate

ROOT = Path(__file__).resolve().parents[2]


def archive(path, source='a'*40, corrupt=False, attestations=True):
    blobs = {}
    def blob(data, media):
        payload = json.dumps(data).encode()
        digest = 'sha256:' + hashlib.sha256(payload).hexdigest()
        blobs['blobs/sha256/' + digest[7:]] = payload
        return dict(mediaType=media, digest=digest, size=len(payload))
    config = blob({'architecture': 'amd64', 'os': 'linux', 'config': {'User': '1100:1100',
        'Labels': {'org.opencontainers.image.revision': source}}}, 'application/vnd.oci.image.config.v1+json')
    runtime = blob({'config': config, 'layers': []}, 'application/vnd.oci.image.manifest.v1+json')
    statements = [blob({'predicateType': kind, 'subject': [{'digest': {'sha256': runtime['digest'][7:]}}]},
                      'application/vnd.in-toto+json') for kind in
                  ('https://slsa.dev/provenance/v0.2', 'https://spdx.dev/Document')]
    att = blob({'config': blob({}, 'application/vnd.oci.image.config.v1+json'), 'layers': statements},
               'application/vnd.oci.image.manifest.v1+json')
    index = blob({'manifests': [runtime, att] if attestations else [runtime]},
                 'application/vnd.oci.image.index.v1+json')
    blobs['index.json'] = json.dumps({'manifests': [index]}).encode()
    if corrupt: blobs['blobs/sha256/' + config['digest'][7:]] = b'bad'
    with tarfile.open(path, 'w') as tar:
        for name, data in blobs.items():
            info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))
    return index['digest']


class ReleaseTests(unittest.TestCase):
    def test_clean_export_required_and_local_export_includes_uncommitted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repo'; root.mkdir()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'code').write_text('old')
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            # Test fixture only; never commits in a project checkout.
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c',
                            'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            (root / 'code').write_text('new')
            (root / 'new-test').write_text('new test')
            p = Path(directory)
            with self.assertRaises(ValueError): m.prepare(p/'rejected', p/'evidence', root=root)
            with redirect_stdout(io.StringIO()):
                data = m.prepare(p/'source', p/'evidence', local=True, root=root)
            self.assertTrue(data['local']); self.assertIn('-local-', data['source_revision'])
            self.assertEqual((p/'source/code').read_text(), 'new')
            self.assertEqual((p/'source/new-test').read_text(), 'new test')
            self.assertFalse((p/'source/.git').exists())

    def test_archive_digest_source_and_attestations(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p/'inputs.json').write_text(json.dumps({'source_revision': 'a'*40}))
            digest = archive(p/'image.tar')
            self.assertEqual(inspect_archive(p/'image.tar', digest, p)['source_revision'], 'a'*40)
            with self.assertRaises(ValueError): inspect_archive(p/'image.tar', 'sha256:'+'0'*64, p)
            for kw in ({'corrupt': True}, {'source': 'b'*40}, {'attestations': False}):
                digest = archive(p/'image.tar', **kw)
                with self.assertRaises(ValueError): inspect_archive(p/'image.tar', digest, p)

    def test_missing_skipped_failed_or_retried_auth_tests_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            def suite(name, count, extra=''):
                return f'<testsuite name="{name}" tests="{count}">' + ''.join(
                    f'<testcase name="case{i}">{extra if i == 0 else ""}</testcase>' for i in range(count)) + '</testsuite>'
            for name, count in EXPECTED.items():
                (p/f'TEST-{name}.xml').write_text(suite(name, count))
            self.assertEqual(reports(p), EXPECTED)
            name = next(iter(EXPECTED)); path = p/f'TEST-{name}.xml'
            for extra in ('<skipped/>', '<failure/>', '<flakyFailure/>'):
                path.write_text(suite(name, EXPECTED[name], extra))
                with self.assertRaises(ValueError): reports(p)
            path.unlink()
            with self.assertRaises(ValueError): reports(p)

    def test_release_contract_rejects_local_unqualified_wrong_component(self):
        record = dict(schema=1, component='backend', repository='LUMII-AILab/clarin-dspace',
            image=m.toolchain()['image'], source='a'*40, version='sha-'+'a'*40,
            digest='sha256:'+'b'*64, config_digest='sha256:'+'c'*64, local=False,
            workflow='.github/workflows/clarin-release.yml', run_id=123,
            checks=dict(oci='passed', authentication='passed', artifact='passed'),
            production_accepted=False, scan_policy='synthetic-report-v1')
        validate(record)
        for bad in ({'local': True}, {'source': 'a'*40+'-local'}, {'checks': {}},
                    {'component': 'frontend'}, {'run_id': 0}, {'production_accepted': True}):
            with self.assertRaises(ValueError): validate(record | bad)

    def test_publisher_rejects_changed_source_reports_run_or_archive(self):
        from record import create
        from verify_record import verify
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); evidence = root/'evidence'; evidence.mkdir()
            data = m.toolchain() | dict(source_commit='a'*40, source_revision='a'*40,
                tag='sha-'+'a'*40, local=False, source_archive_sha256=hashlib.sha256(b'source').hexdigest())
            (evidence/'inputs.json').write_text(json.dumps(data))
            (evidence/'source.tar').write_bytes(b'source')
            digest = archive(root/'backend.oci.tar')
            identity = inspect_archive(root/'backend.oci.tar', digest, evidence)
            (evidence/'qualification.json').write_text(json.dumps(dict(result='passed',
                config_digest=identity['config_digest'], source_revision='a'*40, authentication_tests=EXPECTED)))
            (evidence/'vulnerabilities.json').write_text('{"SchemaVersion":2,"Results":[]}')
            for name in ('jars.sha256', 'maven-version.txt', 'trivy-database.json'):
                (evidence/name).write_text('{}')
            with patch.dict(os.environ, GITHUB_RUN_ID='123', EXPECTED_DIGEST=digest), \
                    patch('verify_record.git', return_value=('a'*40).encode()):
                record = create(evidence)
                (evidence/'release.json').write_text(json.dumps(record))
                self.assertEqual(verify(root), record)
                for name in ('source.tar', 'vulnerabilities.json', 'jars.sha256'):
                    path = evidence/name; original = path.read_bytes()
                    path.write_bytes(original+b' ')
                    with self.assertRaises(ValueError): verify(root)
                    path.write_bytes(original)
                with patch.dict(os.environ, GITHUB_RUN_ID='124'):
                    with self.assertRaises(ValueError): verify(root)
                archive(root/'backend.oci.tar', corrupt=True)
                with self.assertRaises(ValueError): verify(root)

    def test_workflow_has_only_explicit_gated_publication(self):
        workflows = list((ROOT/'.github/workflows').glob('*.yml'))
        self.assertEqual([p.name for p in workflows], ['clarin-release.yml'])
        build, publish = workflows[0].read_text().split('\n  publish:\n')
        for forbidden in ('secrets.', 'packages: write', 'contents: write', 'pull_request_target'):
            self.assertNotIn(forbidden, build)
        for required in ('needs: [build, tests]', "github.event_name == 'workflow_dispatch'", 'inputs.publish',
                         'CLARIN_BACKEND_PUBLISH_ENABLED', 'environment: backend-release', 'verify_record.py'):
            self.assertIn(required, publish)
        self.assertNotIn('build-push-action', publish)
        self.assertIn('qualify.py', build)
        self.assertIn('scan.sh', build)
        self.assertIn('push: false', build)


if __name__ == '__main__': unittest.main()
