# CLARIN backend CI and releases

This repository owns the backend image. Ops owns Apache/Shibboleth, configuration,
deployment and explicit rollback. These procedures build candidates; they do not
select a managed image, initialize a managed database or enable federation.

## CI and build contract

[The workflow](../../.github/workflows/clarin-release.yml) runs on PRs and pushes to
`clarin-v7`, plus manual dispatch. PRs have read-only repository permission, no
registry credentials and no private submodule/ops checkout. The inherited full
unit suite (including deprecated REST) and integration suite remain separate gates;
normal validation checks run and failures are not hidden by automatic test retries.

The candidate build runs the focused authentication suites with normal Maven
style/license/XML/dependency checks, then packages the **complete** installer:
all CLI libraries, configuration, web applications and scripts. It uses the
upstream Ant installation targets in a disposable build image; no database
initialization is run. The existing qualified Tomcat/JDK/OS runtime base remains
pinned. This replaces the local auth builder's partial API/server overlay for new
release candidates; `scripts/authentication/build-local-image.py` remains a legacy
local qualification helper and cannot publish.

[toolchain.json](image/toolchain.json) pins Maven/JDK, runtime, BuildKit, Buildx,
SBOM scanner, image copier and vulnerability scanner. Language resources are pinned
in the root POM to the already-resolved `7.6.2`, replacing the floating range without
an upgrade. No runtime-base upgrade is included. Source export excludes Git,
private submodule contents, ignored files and stale compiled outputs. CI refuses a
dirty checkout. The retained source tar and SHA-256 identify the exact input.

Maven receives the commit timestamp as `project.build.outputTimestamp`; source
archive order, file modes and timestamps are normalized. The exact JAR closure and
builder version are retained. This is a repeatable pinned build procedure, **not a
claim of bit-for-bit identical rebuilds**: inherited plugins, dependency resolution
and provenance timestamps still need independent reproducibility qualification.
Never rebuild to retry publication. Follow [Maven reproducible build guidance](https://maven.apache.org/guides/mini/guide-reproducible-builds.html)
when extending that qualification.

BuildKit exports one Linux amd64 OCI archive with image-bound provenance and SPDX
SBOM. Verification checks every reachable blob, runtime UID, revision and required
attestations before loading. Exact-image qualification checks installed code/JAR
hashes, paths, installation expansion and every required authentication report;
missing, failed, skipped or retried cases fail. The fixed minimum is currently 19
tests across five suites; adding tests is allowed, silently dropping them is not.
Trivy scans the exact runtime including its Java dependencies; scanner errors fail,
findings remain report-only under the existing synthetic policy. The retained SBOM
and reports are evidence, not production security acceptance or signatures.

The artifact smoke check is network-free. It does **not** prove server/database
startup, signed SAML, browser behavior or operational rollback. Ops qualification
must test this exact candidate before integration/publication under the approved
sequence. The full Maven matrix and publication must pass real GitHub runs before
this procedure can be called operational. Local checks alone do not establish that.

## Local review

Requirements: Python 3.12+, Docker/Buildx, public build-input network access and
sufficient build disk. Use a dedicated builder without changing the default:

```sh
python3 -m unittest discover -s ci/release -p 'test_*.py'
bash -n ci/release/scan.sh ci/release/publish.sh
# Copy the exact buildkit_image value from image/toolchain.json.
docker buildx create --name clarin-backend-review --driver docker-container \
  --driver-opt image=moby/buildkit@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e \
  --buildkitd-flags ''
python3 ci/release/build-local.py /tmp/clarin-backend-review --builder clarin-backend-review
# After qualification, remove only this dedicated builder. Keep candidate evidence.
docker buildx rm clarin-backend-review
```

The local command exports current tracked and non-ignored untracked files without
changing Git. It labels the artifact `COMMIT-local-SNAPSHOT`, records `local: true`,
and applies `lv.clarin.qualification=authentication-local-only` for the guarded
disposable ops lab. It cannot create a publishable release. CI uses
`backend-candidate` instead; neither label grants deployment or production acceptance. No services are deployed. It leaves the
loaded image and OCI/evidence directory for disposable ops qualification. Pass `--scan` to also scan the candidate and write a local-only release record;
scanning is always required by CI before a publishable release record exists.
Local output must stay outside the checkout. Synthetic logs/reports stay outside
the workbook; never add private configuration to source or build inputs.

## Approval after successful CI

A push to `clarin-v7` builds and tests once. After the full Maven matrix and
candidate qualification pass, publication waits for owner approval in the
`backend-release` environment. In that run, choose **Review deployments**, select
`backend-release`, then **Approve and deploy**. Despite GitHub's button label, this
job only publishes the retained image and reports; it does not deploy a server or
rebuild the image. PRs cannot publish.

The one-time activation switch is `CLARIN_BACKEND_PUBLISH_ENABLED=true` in
`LUMII-AILab/clarin-dspace`. Keep the environment's owner reviewer and `clarin-v7`
branch restriction configured before enabling it. The switch can disable
publication globally; ordinary releases need only the approval above. Optional
manual dispatch starts a new build/test run with the same approval gate, without
a separate publish checkbox. Do not use it to publish an already waiting candidate.
After real CI validation, review required-check settings for `Maven unit`,
`Maven integration` and `Backend candidate`; do not leave obsolete upstream check
names blocking PRs. No push, merge or approval deploys a server. Frontend publication
retains its separately established automatic mainline flow.

Before the first publication, review GHCR organization creation policy, intended
private visibility, repository linkage and future deployment-reader access for
`ghcr.io/lumii-ailab/clarin-dspace`. If the package does not exist, explicitly set
`CLARIN_BACKEND_BOOTSTRAP=true` for the first authorized publication only. It allows
only an authenticated `NAME_UNKNOWN` response to proceed with package creation;
denied access or other errors fail. Clear it after creation and verify package
visibility/linkage/reader access before any deployment. Never change visibility or
reuse an unrelated package to bypass an access failure. Keep the intended package private and retain the existing repository/reader permissions. See [GitHub package access](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

The publisher receives no source build task. It revalidates the retained OCI,
source, run ID and checksummed evidence, then copies **all** manifests with digest
preservation to `sha-FULL_COMMIT`. Existing different tags are rejected. Reports
are uploaded through a resumable draft GitHub release; existing different report
assets are rejected. The final registry digest must match the candidate exactly.
Publication is repository/workflow trust, not an image-signature scheme.

On interruption, use **Re-run failed jobs**, retaining the successful candidate
artifact (30 days). Do not rerun a successful build just to retry the publisher.
An expired/lost candidate needs a deliberate new source version and qualification;
never move an existing immutable tag. `release.json`, JSON evidence and the checksummed JAR/tool-version reports remain on
the release, while the OCI archive is a time-limited CI artifact. Reports are not
an image backup. A failed build/scan never produces an acceptable release record.

## Ops handoff and remaining release gates

Backend schema 1 is distinct from the frontend contract: component, source commit,
source archive hash, image/index digest, runtime config digest, base/builder pins,
workflow/run, qualification and report hashes. Do not feed it to the existing
frontend selector. Step 4 must add backend selection, schema compatibility
preflight and explicit rollback. Image rollback cannot reverse database migration.
Keep configuration, assets, accounts, permissions, checkpoint and recovery history.

Before step 7 publication, qualify the candidate through the step 3 SP process,
step 4 deployment/rollback tooling, step 5 synthetic persistent dev and step 6
browser/operational tests. Real federation remains disabled. CI does not deploy.

## Inherited workflow audit

Original workflows are preserved byte-for-byte under
[disabled-workflows/upstream](../../.github/disabled-workflows/upstream/).
`build.yml` supplied the full unit/integration matrix retained above. `docker.yml`
and its reusable builder were upstream-only, used floating dependencies and
included redeployment hooks. `tag-release.yml` could retag/push to DockerHub.
Customer-branch dispatch, upstream/customer triage/backport jobs, the empty issue
workflow and obsolete CodeQL workflow are inactive in this fork. Disabling CodeQL
is not a claim of replacement SAST coverage. No upstream files were discarded;
changes to dependencies/scanners remain reviewed work.
