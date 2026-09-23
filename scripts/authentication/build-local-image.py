#!/usr/bin/env python3
"""Build an unpublished local auth candidate on the accepted immutable runtime.

Run focused authentication tests first. This reuses the accepted runtime/dependency
closure and replaces the compiled application and CLI API. It is a qualification
image, not a release pipeline or a managed-image selection command.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASE = 'docker.io/ufal/dspace@sha256:b542b8b4385e22cffdec3277d0a31acddc37c26682af1f497870c90840464fd2'
TAG = 'clarin-dspace-auth:local'

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def main():
    os.umask(0o077)
    # Compile in the original checkout with its reviewed dependency versions.
    run('mvn', '--no-transfer-progress', 'package', '-DskipUnitTests=true',
        '-DskipIntegrationTests=true', '-Dcheckstyle.skip=true', '-Dlicense.skip=true',
        '-Dxml.skip=true', cwd=ROOT,
        env=dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-11-openjdk-amd64'))
    paths = subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT).split(b'\0')
    digest=hashlib.sha256()
    for raw in sorted(set(paths)):
        if not raw: continue
        path=ROOT/os.fsdecode(raw)
        if path.is_file(): digest.update(raw+b'\0'+path.read_bytes())
    source=digest.hexdigest()
    revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    war=ROOT/'dspace-server-webapp/target/dspace-server-webapp-7.6.5.war'
    api=ROOT/'dspace-api/target/dspace-api-7.6.5.jar'
    with tempfile.TemporaryDirectory(prefix='clarin-auth-image-') as directory:
        p=Path(directory)
        # Use the reactor assembly, which supplies additional runtime dependencies.
        shutil.copytree(ROOT/'dspace/target/dspace-installer/webapps/server', p/'server')
        # Match Ant copy_webapps installation-path expansion for this fixed runtime.
        properties = p/'server/WEB-INF/classes/application.properties'
        content = properties.read_text()
        if 'dspace.dir=${dspace.dir}' not in content:
            raise RuntimeError('Unexpected application installation-path configuration')
        properties.write_text(content.replace('${dspace.dir}', '/dspace'))
        shutil.copy(api,p/'dspace-api-7.6.5.jar')
        (p/'Dockerfile').write_text(f'''FROM {BASE}
USER root
RUN rm -rf /dspace/webapps/server
COPY --chown=1100:1100 server/ /dspace/webapps/server/
COPY --chown=1100:1100 dspace-api-7.6.5.jar /dspace/lib/dspace-api-7.6.5.jar
LABEL org.opencontainers.image.revision="{revision}-local" \\
      lv.clarin.qualification="authentication-local-only" \\
      lv.clarin.source.sha256="{source}"
USER 1100:1100
''')
        run('docker','build','--pull=false','--network=none','-t',TAG,str(p))
    image=subprocess.check_output(['docker','image','inspect',TAG,'--format','{{.Id}}'],text=True).strip()
    report={'image':image,'base':BASE,'source_revision':revision,'source_sha256':source,
            'war_sha256':hashlib.sha256(war.read_bytes()).hexdigest(),
            'api_sha256':hashlib.sha256(api.read_bytes()).hexdigest(), 'published':False}
    output=Path('/tmp/clarin-auth-candidate.json');output.write_text(json.dumps(report,indent=2)+'\n')
    print('Local candidate identity:',output)

if __name__=='__main__': main()
