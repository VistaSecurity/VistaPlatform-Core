# The schema image: the SQL the Helm chart's schema-migration and seed-data
# Jobs apply, shipped as a release image instead of inside the chart (#2731).
#
# Helm keeps every chart file and the rendered manifest in one release Secret,
# which Kubernetes caps at 1 MiB. schema.sql and seed.sql are ~1 MB each and
# were in that record twice, so the 5.1.0 commercial chart could not be
# installed at all and Core sat 1% under the ceiling. Here the SQL lives at
# /sql, byte-identical to scripts/database/ at the release tag, and the chart
# carries only the sha256 of schema.sql (charts/vistaplatform/files/schema/
# schema.sha256); the migration Job refuses to apply a schema whose hash is not
# the one the chart was stamped with.
#
# One Dockerfile serves both lines. Core builds it from the public tree
# (release-core.yml); the commercial build (`make build-dist-schema`) is the
# same file from a licensed tree, where services/compliance-engine/ee/content/
# also holds the signed Enterprise content bundle. The public tree has no
# services/*/ee at all and COPY cannot name an optional path, so the service
# directory is copied into a build stage and the bundle picked from it when
# present. A bundle is only ever shipped VERIFIED: the stage checks its
# detached signature against the committed verify key and fails the build
# otherwise, the same check the chart's seed-data Job repeats at install time
# against the key the chart carries.
#
#   docker build -f scripts/database/Dockerfile -t schema:dev .
#   docker run --rm schema:dev            # prints the SHA256SUMS of /sql
ARG RUNTIME_IMAGE=alpine:3.24.2

FROM ${RUNTIME_IMAGE} AS stage
WORKDIR /stage
COPY scripts/database/schema.sql scripts/database/seed.sql ./
COPY services/compliance-engine /src/compliance-engine
RUN set -eu; \
    test -s schema.sql && test -s seed.sql; \
    ee=/src/compliance-engine/ee/content; \
    if [ -f "$ee/frameworks-regulated.sql" ]; then \
      echo "Enterprise content bundle present — verifying its signature before shipping it"; \
      test -s "$ee/frameworks-regulated.sql.sig" || { echo "FATAL: the content bundle is UNSIGNED (frameworks-regulated.sql.sig missing or empty). Run: make sign-content-bundle EDITION_SIGNING_KEY=<path>"; exit 1; }; \
      test -s "$ee/verify-key.pem" || { echo "FATAL: $ee/verify-key.pem is missing — cannot verify the content bundle"; exit 1; }; \
      apk add --no-cache openssl >/dev/null; \
      openssl base64 -d -in "$ee/frameworks-regulated.sql.sig" -out /tmp/bundle.sig; \
      openssl dgst -sha256 -verify "$ee/verify-key.pem" -signature /tmp/bundle.sig "$ee/frameworks-regulated.sql"; \
      mkdir -p ee; \
      cp "$ee/frameworks-regulated.sql" "$ee/frameworks-regulated.sql.sig" ee/; \
    else \
      echo "No Enterprise content bundle in this tree — building the Core schema image"; \
    fi; \
    rm -rf /src; \
    find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS; \
    cat SHA256SUMS

FROM ${RUNTIME_IMAGE}
RUN addgroup -g 1001 -S appgroup && adduser -u 1001 -S appuser -G appgroup
COPY --from=stage --chown=1001:1001 /stage /sql
USER 1001
CMD ["cat", "/sql/SHA256SUMS"]
