# Build arguments are public, pinned by toolchain.json, and retained in provenance.
ARG MAVEN_IMAGE
ARG RUNTIME_IMAGE
FROM ${MAVEN_IMAGE} AS build
WORKDIR /src
COPY . .
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV TZ=UTC LANG=C.UTF-8
# Normal style, license, XML and dependency checks remain enabled. A clean export
# prevents stale classes/reports and excludes user Maven settings/private config.
RUN --mount=type=cache,target=/root/.m2/repository \
    mvn --batch-mode --no-transfer-progress clean install \
      -Dproject.build.outputTimestamp=${SOURCE_DATE_EPOCH} \
      -DskipUnitTests=false \
      -Dtest=ClarinExistingAccountTest,ShibGroupLoggingTest,ClarinReturnUrlTest \
      -DfailIfNoTests=false -DskipIntegrationTests=false \
      -Dit.test=ClarinShibbolethLoginFilterIT,ClarinShibbolethAuthAssing2GroupsIT
# Run upstream's installation targets in this isolated image, never database
# initialization. Ant is already a pinned application dependency (1.10.15).
WORKDIR /src/dspace/target/dspace-installer
RUN --network=none java -cp 'lib/ant-1.10.15.jar:lib/ant-launcher-1.10.15.jar' \
      org.apache.tools.ant.Main init_installation update_configs update_code update_webapps \
    && printf '%s\n' "${SOURCE_REVISION}" > /dspace/config/VERSION_D.txt \
    && mkdir -p /evidence/api /evidence/rest-unit /evidence/rest-integration \
    && cp /src/dspace-api/target/surefire-reports/TEST-*.xml /evidence/api/ \
    && cp /src/dspace-server-webapp/target/surefire-reports/TEST-*.xml /evidence/rest-unit/ \
    && cp /src/dspace-server-webapp/target/failsafe-reports/TEST-*.xml /evidence/rest-integration/ \
    && (cd /dspace && find lib webapps -type f -name '*.jar' -print0 | sort -z | xargs -0 sha256sum) > /evidence/jars.sha256 \
    && mvn --version > /evidence/maven-version.txt
FROM ${RUNTIME_IMAGE}
USER root
# Replace the entire application closure, not a single API JAR; retain the
# qualified Tomcat/JDK/OS image and its existing Tomcat startup configuration.
RUN rm -rf /dspace
COPY --from=build --chown=1100:1100 /dspace/ /dspace/
COPY --from=build /evidence/ /usr/share/clarin-build/
COPY --chown=1100:1100 scripts/restart_debug/ /usr/local/tomcat/bin/
COPY --chown=1100:1100 scripts/index-scripts/ /dspace/bin/
RUN mkdir -p /dspace/assetstore && chown 1100:1100 /dspace/assetstore \
    && chmod u+x /dspace/bin/* /usr/local/tomcat/bin/*.sh
ARG SOURCE_REVISION
ARG SOURCE_ARCHIVE_SHA256
ARG QUALIFICATION_SCOPE=backend-candidate
LABEL lv.clarin.qualification="${QUALIFICATION_SCOPE}" \
      org.opencontainers.image.source="https://github.com/LUMII-AILab/clarin-dspace" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      lv.clarin.source.archive.sha256="${SOURCE_ARCHIVE_SHA256}"
USER 1100:1100
