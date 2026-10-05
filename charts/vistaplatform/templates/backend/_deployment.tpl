{{/*
Named template that emits a Deployment + Service + PodDisruptionBudget for one
backend entry. Inputs (dict): ctx (root context), name (service name), svc
(value entry from .Values.backends).
*/}}
{{- define "vistaplatform.backend" -}}
{{- $ctx := .ctx -}}
{{- $name := .name -}}
{{- $svc := .svc -}}
{{- $needs := default (dict) $svc.needs -}}
{{- $secrets := default (dict) $svc.secrets -}}
{{- $replicas := default $ctx.Values.defaultReplicas $svc.replicas -}}
{{- $image := default (dict) $svc.image -}}
{{- $imageTag := default $ctx.Values.image.tag $image.tag -}}
{{- $imageDigest := $image.digest -}}
{{/*
SERVICE_VERSION is the RELEASE tag (e.g. v2.5.3) — uniform across every
service so the About page's skew check has a valid equality key. It is
deliberately NOT overridden with the image digest: digests are unique per
service, so folding them in here made every service report a different
"tag" and produced a permanent false "skew detected" on digest-pinned
(ECR/EKS) installs. The digest is surfaced separately via
SERVICE_IMAGE_DIGEST below as per-pod identity.
*/}}
{{- $serviceVersion := default $ctx.Chart.AppVersion $imageTag -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $name }}
  labels:
    {{- include "vistaplatform.labels" $ctx | nindent 4 }}
    app.kubernetes.io/component: {{ $name }}
spec:
  replicas: {{ $replicas }}
  {{/*
  Per-backend update strategy. Defaults to Kubernetes's `RollingUpdate`, which
  is correct for stateless backends. Services that hold a ReadWriteOnce PVC
  (e.g. pcap-processor + pcap-uploads) MUST use `Recreate`: rolling update
  schedules a new pod while the old one still owns the volume, the new pod
  hangs on Multi-Attach, the old pod won't terminate until the new one's
  Ready, and the upgrade deadlocks. See pcap-processor's `strategy:` entry
  in values.yaml.

  admin-service mounts the licence-reports PVC (licensing.reports.persistence),
  so on a ReadWriteOnce claim it must not surge either — but it gets a
  RollingUpdate with `maxSurge: 0, maxUnavailable: 1`, NOT `Recreate`, unless
  its own `strategy:` says otherwise (e.g. with a ReadWriteMany class). With no
  surge the old pod is removed before the new one is created, so nothing waits
  on a pod stuck on Multi-Attach and there is no deadlock.

  Why not `Recreate`: admin-service was a RollingUpdate Deployment in every
  release before the licence-reports PVC, and a LIVE Deployment cannot be
  switched to Recreate by Helm's server-side apply (Helm 4's default). The API
  server defaulted `rollingUpdate: {maxSurge: 25%, maxUnavailable: 25%}` onto
  it, no field manager owns that default, SSA keeps unowned fields — and it
  treats an explicit `rollingUpdate: null` as "no opinion", so a null does not
  remove it either (checked against a real API server). The merged object is
  invalid and the WHOLE upgrade fails: "spec.strategy.rollingUpdate: Forbidden:
  may not be specified when strategy type is 'Recreate'". Staying on
  RollingUpdate and owning both fields explicitly is valid from any prior state.

  The same trap applies to ANY Deployment moved to Recreate after it has been
  deployed, so never make Recreate the new default of an existing backend.
  scripts/test-chart-update-strategy.mjs pins the Recreate set.
  */}}
  {{- $strategy := $svc.strategy }}
  {{- if and (not $strategy) (eq $name "admin-service") $ctx.Values.licensing.reports.persistence.enabled (ne $ctx.Values.licensing.reports.persistence.accessMode "ReadWriteMany") }}
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 1
  {{- else if $strategy }}
  strategy:
    type: {{ $strategy }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "vistaplatform.selectorLabels" (dict "ctx" $ctx "component" $name) | nindent 6 }}
  template:
    metadata:
      annotations:
        # envFrom ConfigMap values are injected at pod START only. Without this
        # checksum, a helm upgrade that changes any app-config value
        # (COOKIE_DOMAIN, WEB_UI_BASE_URL, ...) updates the ConfigMap while
        # running pods keep the old values in memory — no error anywhere (this
        # silently broke admin login once). Hashing the rendered ConfigMap into
        # the pod template makes Helm itself roll the Deployments whenever the
        # effective config changes, whether or not Reloader is installed.
        checksum/config: {{ include (print $ctx.Template.BasePath "/configmap-app.yaml") $ctx | sha256sum }}
        {{- if $ctx.Values.serviceMtls.enabled }}
        # Stakater Reloader restarts this Deployment when its mTLS cert Secret
        # is rotated by cert-manager, so the pod picks up the new cert without
        # manual intervention (rotation happens out-of-band where Helm cannot
        # see it — the checksum above does not cover it). Requires Reloader
        # installed in the cluster.
        secret.reloader.stakater.com/reload: {{ $name }}-mtls
        {{- end }}
      labels:
        {{- include "vistaplatform.labels" $ctx | nindent 8 }}
        app.kubernetes.io/component: {{ $name }}
    spec:
      automountServiceAccountToken: false
      securityContext:
        {{- include "vistaplatform.podSecurityContext" $ctx | nindent 8 }}
      {{- $antiAffinity := include "vistaplatform.podAntiAffinity" (dict "ctx" $ctx "component" $name) }}
      {{- $colocateWith := $svc.colocateWith }}
      {{- if or $antiAffinity $colocateWith }}
      affinity:
        {{- if $antiAffinity }}
        {{- $antiAffinity | nindent 8 }}
        {{- end }}
        {{- if $colocateWith }}
        {{/*
        Hard pod-affinity: schedule this pod onto the same node as the
        named component. Used for services that share a ReadWriteOnce PVC
        (e.g. sensor-manager + pcap-processor share pcap-uploads). Without
        this, the scheduler can land them on different nodes and the second
        pod hits a Multi-Attach volume error.
        */}}
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  {{- include "vistaplatform.selectorLabels" (dict "ctx" $ctx "component" $colocateWith) | nindent 18 }}
              topologyKey: kubernetes.io/hostname
        {{- end }}
      {{- end }}
      {{- with $ctx.Values.image.pullSecrets }}
      imagePullSecrets:
        {{- range . }}
        - name: {{ . }}
        {{- end }}
      {{- end }}
      {{- if $needs.postgres }}
      initContainers:
        {{/*
        wait-for-schema — hold this backend's main container until the database
        carries THIS chart's schema.

        The gate is the schema-migration completion marker: the row in
        public.schema_migration_status keyed by the content hash of the shipped
        schema.sql, which jobs/schema-migration.yaml writes only after the whole
        file has applied (ON_ERROR_STOP=1). seed-data gates on the same row via
        the same helper (vistaplatform.schemaMarkerQuery), so the hash cannot
        drift between the writer and its readers.

        Why not a sentinel table: this used to wait for public.tenants, which is
        true on EVERY upgrade (and early in a fresh install's apply). The
        schema-migration Job is a plain release resource, not a pre-upgrade hook,
        so `helm upgrade` starts the new pods while the Job is still adding
        columns. On the 4.1.0 upgrade that surfaced as a backend's first query
        failing with SQLSTATE 42703 (undefined column) against a column the Job
        had not added yet. Keying on the hash waits for the new schema rather
        than passing on the previous release's tables or its marker.

        When the schema did not change between releases, the marker row already
        exists and the wait passes on the first query.

        schemaMigration.enabled=false: the chart never writes a marker, so waiting
        for one would never end. The gate falls back to the sentinel table — the
        only thing the chart can know about a schema applied out of band.

        Timeout: gives up after WAIT_TIMEOUT_SECONDS (same ~10m budget as
        seed-data) with the reason and the last psql error, and exits 1. That is
        not fatal: kubelet restarts the init container with backoff and the pod
        proceeds once the marker lands, but a slow or failed migration shows up
        as Init:Error / restarts instead of a silent hang. Under RollingUpdate the
        old pods keep serving meanwhile, so a failed migration stalls the rollout
        instead of starting new code against a half-applied schema.

        The pod template embeds the schema hash, so a schema change rolls every
        backend (it would anyway: releases change the image tag too).
        scripts/test-chart-wait-for-schema.mjs pins all of this and executes the
        script against a stub psql.
        */}}
        - name: wait-for-schema
          image: "{{ $ctx.Values.schemaMigration.image.repository }}:{{ $ctx.Values.schemaMigration.image.tag }}"
          imagePullPolicy: {{ $ctx.Values.image.pullPolicy }}
          securityContext:
            {{- include "vistaplatform.containerSecurityContext" $ctx | nindent 12 }}
          env:
            {{- if $ctx.Values.datastores.postgres.enabled }}
            - name: PGHOST
              value: postgres
            - name: PGPORT
              value: "5432"
            - name: PGUSER
              value: {{ $ctx.Values.datastores.postgres.user | quote }}
            - name: PGDATABASE
              value: {{ $ctx.Values.datastores.postgres.db | quote }}
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.generatedSecretName" $ctx }}
                  key: postgres-password
            {{- if $ctx.Values.datastores.postgres.tls.enabled }}
            # Postgres requires TLS (#87 Phase 3); the wait-for-schema psql/pg_isready
            # (libpq) verify the server using the CA from the pod's mTLS cert mount.
            - name: PGSSLMODE
              value: verify-full
            - name: PGSSLROOTCERT
              value: /app/certs/ca.crt
            {{- end }}
            {{- else }}
            # External DB (e.g. RDS): connect via the canonical DATABASE_URL from
            # the platform secret (correct creds + sslmode=require). The PGHOST/
            # PGPASSWORD path uses the generated in-cluster postgres-password,
            # which is meaningless for an external DB — the init container would
            # never authenticate and would hang forever. Mirrors the fix in the
            # schema-migration / seed Jobs.
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: database-url
            {{- end }}
          command:
            - sh
            - -c
            - |
              WAIT_TIMEOUT_SECONDS=600
              ERR=/tmp/wait-for-schema.err
              {{- if $ctx.Values.datastores.postgres.enabled }}
              db_ready() { pg_isready -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" >/dev/null 2>&1; }
              db_query() { psql -tAc "$1" 2>"$ERR"; }
              {{- else }}
              db_ready() { pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; }
              db_query() { psql -d "$DATABASE_URL" -tAc "$1" 2>"$ERR"; }
              {{- end }}
              start=$(date +%s)
              elapsed() { echo $(( $(date +%s) - start )); }
              give_up() {
                echo "ERROR: $1 after $(elapsed)s (limit ${WAIT_TIMEOUT_SECONDS}s)."
                if [ -s "$ERR" ]; then
                  echo "  last psql error:"
                  sed 's/^/    /' "$ERR"
                fi
                echo "  $2"
                echo "  Exiting 1; kubelet retries this init container with backoff."
                exit 1
              }
              echo "wait-for-schema ({{ $name }}): waiting for Postgres to accept connections..."
              until db_ready; do
                [ "$(elapsed)" -ge "$WAIT_TIMEOUT_SECONDS" ] && give_up "Postgres is not accepting connections" "Check the postgres pod, or DATABASE_URL for an external database."
                sleep 2
              done
              {{- if $ctx.Values.schemaMigration.enabled }}
              {{- $schemaHash := include "vistaplatform.schemaHash" $ctx }}
              echo "Postgres up. Waiting for schema-migration to record schema {{ $schemaHash }} in public.schema_migration_status..."
              n=0
              until [ "$(db_query "{{ include "vistaplatform.schemaMarkerQuery" $ctx }}")" = "1" ]; do
                if [ "$(elapsed)" -ge "$WAIT_TIMEOUT_SECONDS" ]; then
                  # Keep the gate's own psql error for give_up; this query is context only.
                  cp "$ERR" "$ERR.gate"
                  latest=$(db_query "SELECT schema_hash || ' (app ' || coalesce(app_version, '?') || ', applied ' || applied_at || ')' FROM public.schema_migration_status ORDER BY applied_at DESC LIMIT 1")
                  mv "$ERR.gate" "$ERR"
                  give_up "schema {{ $schemaHash }} has not been recorded as applied" "Latest recorded schema: ${latest:-none}. Check the schema-migration Job: kubectl logs -l app.kubernetes.io/component=schema-migration"
                fi
                n=$((n + 1))
                [ $((n % 10)) -eq 0 ] && echo "  still waiting for schema-migration ($(elapsed)s)..."
                sleep 3
              done
              echo "Schema {{ $schemaHash }} applied. Starting {{ $name }}."
              {{- else }}
              echo "Postgres up. schemaMigration.enabled=false: this chart does not migrate the database, so there is no completion marker to wait for."
              echo "Waiting only for a schema to exist (sentinel: public.tenants)..."
              until [ "$(db_query "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='tenants'")" = "1" ]; do
                [ "$(elapsed)" -ge "$WAIT_TIMEOUT_SECONDS" ] && give_up "no schema found (public.tenants is missing)" "With schemaMigration.enabled=false, apply scripts/database/schema.sql yourself before starting the backends."
                sleep 3
              done
              echo "Schema present. Starting {{ $name }}."
              {{- end }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            {{- if $ctx.Values.datastores.postgres.tls.enabled }}
            # CA for verifying the Postgres server cert (the pod-level mtls volume
            # exists because postgres.tls.enabled requires serviceMtls.enabled).
            - name: mtls
              mountPath: /app/certs
              readOnly: true
            {{- end }}
      {{- end }}
      containers:
        - name: {{ $name }}
          image: {{ include "vistaplatform.image" (dict "ctx" $ctx "repo" $name "tag" $imageTag "digest" $imageDigest) }}
          imagePullPolicy: {{ $ctx.Values.image.pullPolicy }}
          securityContext:
            {{- include "vistaplatform.containerSecurityContext" $ctx | nindent 12 }}
          ports:
            - name: http
              containerPort: 8080
            {{- if $ctx.Values.serviceMtls.enabled }}
            # mTLS API listener (real endpoints). 8080 is reduced to the plain
            # /health probe listener in this mode (see kubelet probes below).
            - name: https-mtls
              containerPort: 8443
            {{- end }}
            {{- if and $ctx.Values.agentMtls.enabled (hasKey $ctx.Values.agentMtls.backends $name) }}
            # Agent/sensor mTLS passthrough listener (#581). The agent's
            # per-tenant client cert terminates here (RequireAnyClientCert);
            # AgentAuth/SensorAuth verify it against the tenant CA and fail
            # closed when absent.
            - name: agent-mtls
              containerPort: {{ $ctx.Values.agentMtls.port }}
            {{- end }}
          envFrom:
            - configMapRef:
                name: {{ include "vistaplatform.fullname" $ctx }}-config
          env:
            # Release tag — surfaced on /health so the About page can detect
            # version skew when a per-service image.tag override leaves a pod
            # on a stale image after a chart upgrade. Uniform across the
            # release (the digest, which is per-pod, goes in the next env).
            - name: SERVICE_VERSION
              value: {{ $serviceVersion | quote }}
            {{- if $imageDigest }}
            # Per-pod image content digest when the image is digest-pinned.
            # Informational identity for the About page; not a skew key.
            - name: SERVICE_IMAGE_DIGEST
              value: {{ $imageDigest | quote }}
            {{- end }}
            {{- if and (not $ctx.Values.agentMtls.enabled) (hasKey $ctx.Values.agentMtls.backends $name) }}
            # Explicit opt-out. The services default AGENT_MTLS_REQUIRED to true,
            # so silence here would fail closed — and with no passthrough listener
            # the peer cert on this hop is the *mesh* cert (CN = a service
            # identity), whose CN can never match the agent id, so every agent
            # request would 401 (#922). Stating "false" keeps that a deliberate,
            # inspectable choice rather than an accident of an absent variable:
            # agents on this release authenticate by their id alone.
            - name: AGENT_MTLS_REQUIRED
              value: "false"
            {{- end }}
            {{- if and $ctx.Values.agentMtls.enabled (hasKey $ctx.Values.agentMtls.backends $name) }}
            # Fail-closed agent/sensor mTLS enforcement (#581). Requires the
            # dedicated passthrough listener (port below) to receive the real
            # client cert via edge TLS passthrough.
            - name: AGENT_MTLS_REQUIRED
              value: "true"
            - name: AGENT_TLS_PORT
              value: {{ $ctx.Values.agentMtls.port | quote }}
            {{- with (index $ctx.Values.agentMtls.backends $name) }}
            {{- if .dnsName }}
            # Passthrough URL advertised to agents/sensors in the registration
            # response (#1033): registration happens on the edge host (no
            # client cert yet), then the agent switches here for all later
            # calls so its client cert survives to the backend.
            - name: AGENT_MTLS_ADVERTISED_URL
              value: {{ printf "https://%s:%v" .dnsName $ctx.Values.agentMtls.port | quote }}
            {{- end }}
            {{- end }}
            {{- end }}
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.generatedSecretName" $ctx }}
                  key: postgres-password
            {{- if $ctx.Values.datastores.postgres.enabled }}
            {{- if $ctx.Values.serviceRls.enabled }}
            # RLS role split (#218): the normal per-request path connects as the
            # non-owner crypto_app role (NOBYPASSRLS) so tenant_isolation policies
            # are enforced; the deliberate cross-tenant path uses crypto_bypass
            # (BYPASSRLS). Same host/db/sslmode as the owner URL — only the user
            # differs. Both reuse $(POSTGRES_PASSWORD) (the roles share the
            # postgres password; see values.yaml serviceRls).
            - name: DATABASE_URL
              value: {{ include "vistaplatform.databaseURLForUser" (dict "ctx" $ctx "user" $ctx.Values.serviceRls.roleApp) | quote }}
            - name: BYPASS_DATABASE_URL
              value: {{ include "vistaplatform.databaseURLForUser" (dict "ctx" $ctx "user" $ctx.Values.serviceRls.roleBypass) | quote }}
            {{- else }}
            - name: DATABASE_URL
              value: {{ include "vistaplatform.databaseURL" $ctx | quote }}
            {{- end }}
            {{- else }}
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: database-url
            {{- end }}
            {{- if $needs.nats }}
            {{- if $ctx.Values.datastores.nats.tls.enabled }}
            # NATS mTLS (#87 Phase 4): no shared token — connect with the pod's
            # per-service client cert. shared/events nats_tls.go auto-applies
            # nats.ClientCert + nats.RootCAs when these NATS_TLS_* paths are set.
            - name: NATS_URL
              value: "nats://nats:4222"
            - name: NATS_TLS_CERT_PATH
              value: /app/certs/tls.crt
            - name: NATS_TLS_KEY_PATH
              value: /app/certs/tls.key
            - name: NATS_TLS_CA_PATH
              value: /app/certs/ca.crt
            {{- else }}
            - name: NATS_TOKEN
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.generatedSecretName" $ctx }}
                  key: nats-token
            # NATS server is configured for TOKEN auth (authorization { token: ...
            # } in nats.conf). NATS URL syntax for token auth is nats://TOKEN@host
            # — no colon before @. The earlier `nats://:TOKEN@host` form is
            # user/password-pair syntax with empty user, which NATS rejects when
            # the server expects a bare token. v0.1.2 retires shared-token auth
            # entirely in favor of per-service mTLS to NATS — see
            # CHART-V0.1.2-MTLS-PLAN.md §6.
            - name: NATS_URL
              value: "nats://$(NATS_TOKEN)@nats:4222"
            {{- end }}
            {{- end }}
            {{- if or $needs.redis $secrets.redisUrl }}
            {{- if $ctx.Values.datastores.redis.enabled }}
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.generatedSecretName" $ctx }}
                  key: redis-password
            - name: REDIS_URL
              value: {{ include "vistaplatform.redisURL" $ctx | quote }}
            {{- else }}
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: redis-url
            {{- end }}
            {{- end }}
            {{- if $secrets.jwtSecret }}
            {{- if $ctx.Values.jwtSigning.enabled }}
            {{/*
              #584. JWT_SECRET is now the LEGACY shared secret, injected only
              while jwtSigning.acceptLegacyHmac is on so that sessions minted
              before the cutover keep verifying. Turning that off removes the
              variable from every pod but the two issuers, which is the point at
              which a leak of it forges nothing.

              The issuers keep it unconditionally: they need it to verify their
              own pre-cutover refresh tokens, and they fall back to HS256
              minting if no signing key is mounted.
            */}}
            {{- if or $ctx.Values.jwtSigning.acceptLegacyHmac (has $name (list "auth-service" "admin-service")) }}
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: jwt-secret
            {{- end }}
            {{/*
              Where verifiers get the issuer's PUBLIC keys. Plaintext :8080 on
              purpose — under serviceMtls the API listener moves to :8443 and
              demands a client certificate, and needing a client cert to fetch
              the keys required to authenticate is a circularity with no
              security value. JWKS is public key material.
            */}}
            - name: JWT_JWKS_URL
              value: {{ $ctx.Values.jwtSigning.jwksUrl | default "http://auth-service:8080/.well-known/jwks.json" | quote }}
            - name: JWT_JWKS_INTERVAL
              value: {{ $ctx.Values.jwtSigning.jwksRefreshSeconds | default 300 | quote }}
            {{- if has $name (list "auth-service" "admin-service") }}
            {{/*
              The PRIVATE key, named only for the two token issuers. Every other
              service in this loop gets the JWKS URL above and nothing else —
              that asymmetry IS the fix. Adding a service here is a security
              decision, not a wiring detail; scripts/test-chart-jwt-signing.mjs
              fails if this list widens.
            */}}
            - name: {{ if eq $name "auth-service" }}AUTH_JWT{{ else }}PLATFORM_JWT{{ end }}_SIGNING_KEY_FILE
              value: /app/jwt-keys/signing-key.pem
            {{- end }}
            {{- else }}
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: jwt-secret
            {{- end }}
            {{- end }}
            {{- if $secrets.internalAuthSecret }}
            - name: INTERNAL_AUTH_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: internal-auth-secret
            {{- end }}
            {{- if and (include "vistaplatform.aiProvider" $ctx) $ctx.Values.ai.apiKey.existingSecret }}
            # The generative provider's credential, under the name
            # AI_API_KEY_ENV points at. Injected on EVERY backend, from one
            # place, because `GET /tenant/ai` is the single availability answer
            # both UIs read before rendering any AI control — and auth-service,
            # which serves it, owns no seam. The anthropic client refuses to
            # construct without a key, so an auth-service that did not have one
            # would report provider_configured:false and hide every AI button in
            # the product while the capability underneath worked.
            #
            # The env var NAME is resolved once by the same helper that writes
            # AI_API_KEY_ENV into the ConfigMap, so the two cannot disagree.
            - name: {{ include "vistaplatform.aiAPIKeyEnvVar" $ctx }}
              valueFrom:
                secretKeyRef:
                  name: {{ $ctx.Values.ai.apiKey.existingSecret }}
                  key: {{ $ctx.Values.ai.apiKey.existingSecretKey | default "api-key" }}
            {{- end }}
            {{- if eq $name "admin-service" }}
            {{/*
              This install's identity (secrets-install.yaml). admin-service
              alone reads it: it records it in platform_install on first boot
              (after which the database copy is authoritative) and checks an
              install-bound licence against it. No other service has a use for
              it, so no other service gets it.
            */}}
            - name: INSTALL_ID
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.installSecretName" $ctx }}
                  key: install-id
            {{/*
              The install signing key (same Secret, mounted as a file below):
              admin-service signs every licence usage report with it. A file,
              not an env var, so the private key is not in the process
              environment.
            */}}
            - name: INSTALL_SIGNING_KEY_FILE
              value: /etc/vistaplatform/install-signing/signing-key.pem
            {{/*
              Where the catalogue feeds spool downloaded archives (the
              catalog-feed-spool emptyDir below, sized by
              catalogFeeds.spool.sizeLimit). Decision 13: the OSV archive cap
              is 2 GiB and Ubuntu's export alone is ~705 MiB, which is more
              than an unsized /tmp should be trusted with.
            */}}
            - name: CATALOG_FEEDS_SPOOL_DIR
              value: /var/spool/catalog-feeds
            {{- if $ctx.Values.licensing.reports.persistence.enabled }}
            - name: LICENSE_REPORTS_DIR
              value: {{ $ctx.Values.licensing.reports.dir | quote }}
            {{- end }}
            {{/*
              Automatic usage-report delivery (licensing.reporting). Empty
              endpoint = off, and then nothing is rendered. The values schema
              already refuses a non-https URL; this repeats it so a render
              that skips schema validation still cannot point the transmitter
              at a plaintext or credential-bearing URL.
            */}}
            {{- $reporting := $ctx.Values.licensing.reporting | default dict }}
            {{- $endpoint := $reporting.endpoint | default "" | trim }}
            {{- if $endpoint }}
            {{- if not (regexMatch "^https://[^\\s/?#@]+(/[^\\s?#]*)?$" $endpoint) }}
            {{- fail (printf "licensing.reporting.endpoint must be an https:// URL with a host and no credentials, query or fragment (got %q)" $endpoint) }}
            {{- end }}
            - name: LICENSE_REPORTING_ENDPOINT
              value: {{ $endpoint | quote }}
            - name: LICENSE_REPORTING_INTERVAL_MINUTES
              value: {{ $reporting.intervalMinutes | default 60 | int | toString | quote }}
            {{- end }}
            {{- end }}
            {{- if $secrets.encryptionMasterKey }}
            - name: ENCRYPTION_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.platformSecretName" $ctx }}
                  key: encryption-master-key
            {{- end }}
            {{- if and $secrets.stripeKeys (include "vistaplatform.billingEnabled" $ctx) }}
            - name: STRIPE_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.billingSecretName" $ctx }}
                  key: stripe-secret-key
            - name: STRIPE_PUBLISHABLE_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.billingSecretName" $ctx }}
                  key: stripe-publishable-key
            - name: STRIPE_WEBHOOK_SECRET
              valueFrom:
                secretKeyRef:
                  name: {{ include "vistaplatform.billingSecretName" $ctx }}
                  key: stripe-webhook-secret
            {{- end }}
            {{- if eq $name "cluster-sensor-service" }}
            {{/*
              Explicit external scan targets (#2014 W5.13b). Rendered here, not
              via extraEnv, so a customer extraEnv list cannot drop it; the
              service reads a missing or unrecognised value as OFF. hasKey, not
              `default`: `false | default true` is true.
            */}}
            {{- $ext := (($ctx.Values.discovery | default dict).explicitExternalTargets) | default dict }}
            {{- $extEnabled := false }}
            {{- if hasKey $ext "enabled" }}{{- $extEnabled = $ext.enabled }}{{- end }}
            - name: DISCOVERY_EXPLICIT_EXTERNAL_TARGETS_ENABLED
              value: {{ ternary "true" "false" (eq (toString $extEnabled) "true") | quote }}
            - name: DISCOVERY_EXTERNAL_TARGET_MAX_ADDRESSES
              value: {{ $ext.maxAddressesPerTarget | default 4096 | int | toString | quote }}
            - name: DISCOVERY_EXTERNAL_JOB_MAX_ADDRESSES
              value: {{ $ext.maxAddressesPerJob | default 16384 | int | toString | quote }}
            {{- /* Scan-plan probe budget (#2170 H19); the service fails closed to its default. */}}
            - name: DISCOVERY_MAX_JOB_PROBES
              value: {{ (($ctx.Values.discovery | default dict).maxJobProbes) | default 25000000 | int64 | toString | quote }}
            {{- /* Scan-plan unit share-out per replica (#2170 H33); the service fails closed to its defaults. */}}
            - name: DISCOVERY_MAX_CONCURRENT_UNITS
              value: {{ (($ctx.Values.discovery | default dict).maxConcurrentUnits) | default 16 | int | toString | quote }}
            - name: DISCOVERY_MAX_CONCURRENT_UNITS_PER_TENANT
              value: {{ (($ctx.Values.discovery | default dict).maxConcurrentUnitsPerTenant) | default 4 | int | toString | quote }}
            {{- end }}
            {{- /*
              Backends that intentionally reach customer RFC1918 networks:
              device interrogation talks to appliances; and any backend
              whose values entry sets `privateNetworkDialer: true` — an
              Enterprise-only connector host declares itself that way, inside
              its own edition fence, so this Core-shipped template never names
              it. Give their application-level dial guard the same
              installation-specific pod/Service exclusions as NetworkPolicy,
              so a private-endpoint permission cannot be used to reach this
              cluster — nor a connector's "test connection" be used to map it.
              device-interrogation-service is a floor a values override cannot
              remove. inventory-service is deliberately NOT on it: it used to
              host the NetBox and CMDB connectors, but they moved to an
              Enterprise-only service (platform ADR-0002 M2/M3) and nothing it
              still runs dials a customer private address — its only outbound
              call is the configured ai.provider endpoint, which does not read
              this variable.
            */}}
            {{- $privateDialer := or (eq $name "device-interrogation-service") (eq (toString $svc.privateNetworkDialer) "true") }}
            {{- if $privateDialer }}
            {{- $networkPolicy := $ctx.Values.networkPolicy | default dict }}
            {{- $internalCIDRs := $networkPolicy.clusterInternalCIDRs | default (list) }}
            {{- if empty $internalCIDRs }}
            {{- fail (printf "networkPolicy.clusterInternalCIDRs must contain this cluster's pod and Service CIDRs; %s dials customer private networks and uses it to block application-level access to platform-internal addresses" $name) }}
            {{- end }}
            - name: VISTA_PLATFORM_INTERNAL_CIDRS
              value: {{ join "," $internalCIDRs | quote }}
            {{- end }}
            {{- /*
              The external-targets variables come ONLY from
              discovery.explicitExternalTargets. An extraEnv entry would be
              rendered after the chart's and win (the last duplicate wins), so
              `enabled: false` could be silently undone by extraEnv — refuse
              the render instead (#2014 W5.13b review N1).
            */}}
            {{- range $svc.extraEnv }}
            {{- $envName := toString (.name | default "") }}
            {{- if or (hasPrefix "DISCOVERY_EXTERNAL_" $envName) (hasPrefix "DISCOVERY_EXPLICIT_EXTERNAL_" $envName) }}
            {{- fail (printf "backends.%s.extraEnv sets %s: the explicit external scan target settings are configured only under discovery.explicitExternalTargets (enabled, maxAddressesPerTarget, maxAddressesPerJob) — an extraEnv entry would silently override them. Remove it and set the value there." $name $envName) }}
            {{- end }}
            {{- if and $privateDialer (eq $envName "VISTA_PLATFORM_INTERNAL_CIDRS") }}
            {{- fail (printf "backends.%s.extraEnv must not set VISTA_PLATFORM_INTERNAL_CIDRS; configure networkPolicy.clusterInternalCIDRs so the application and NetworkPolicy use the same source of truth" $name) }}
            {{- end }}
            {{- end }}
            {{- /*
              monitoring-service's probe targets are rendered here, not kept in
              its values.yaml extraEnv list: Helm replaces lists, so a customer
              extraEnv (one entry is enough) dropped all of them, and the
              service then fell back to compose-era hosts this chart never
              creates (http://api-gateway:80, http://nats:8222) and reported
              both as down. An extraEnv entry with the same name replaces the
              chart's value, so each stays overridable without a duplicate env
              name. The empty values are deliberate: no in-cluster api-gateway
              pod exists, and "" opts those probes out.
            */}}
            {{- if eq $name "monitoring-service" }}
            {{- $customerEnv := dict }}
            {{- range $svc.extraEnv }}
            {{- $_ := set $customerEnv (toString (.name | default "")) true }}
            {{- end }}
            {{- range $default := list
                  (dict "name" "NATS_MONITOR_URL" "value" "http://nats-headless:8222")
                  (dict "name" "API_GATEWAY_URL" "value" "")
                  (dict "name" "TRAEFIK_API_URL" "value" "")
                  (dict "name" "TRAEFIK_DASHBOARD_URL" "value" "") }}
            {{- if not (hasKey $customerEnv $default.name) }}
            - name: {{ $default.name }}
              value: {{ $default.value | quote }}
            {{- end }}
            {{- end }}
            {{- end }}
            {{- with $svc.extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
            {{/*
            Synthetic-edge checks: monitoring-service consumes a JSON-encoded
            list via SYNTHETIC_CHECKS_JSON. Sourced from .Values.monitoring.
            syntheticChecks so customers can declare checks in a structured
            YAML list rather than through extraEnv. See values.yaml
            `monitoring:` block.
            */}}
            {{- if and (eq $name "monitoring-service") $ctx.Values.monitoring }}
            {{- with $ctx.Values.monitoring.syntheticChecks }}
            - name: SYNTHETIC_CHECKS_JSON
              value: {{ . | toJson | quote }}
            {{- end }}
            {{- end }}
          resources:
            {{- toYaml $svc.resources | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: license
              mountPath: {{ $ctx.Values.license.mountPath }}
              readOnly: true
            {{- if $ctx.Values.serviceMtls.enabled }}
            - name: mtls
              mountPath: /app/certs
              readOnly: true
            {{- end }}
            {{- if and $ctx.Values.jwtSigning.enabled (has $name (list "auth-service" "admin-service")) }}
            {{/*
              The JWT signing PRIVATE key, mounted ONLY into the two token
              issuers (#584). Every other backend in this loop reaches the
              public half over JWKS and never sees this Secret — the whole point
              is that 15 of the 17 services cannot mint a token.
            */}}
            - name: jwt-signing
              mountPath: /app/jwt-keys
              readOnly: true
            {{- end }}
            {{- if eq $name "admin-service" }}
            - name: install-signing
              mountPath: /etc/vistaplatform/install-signing
              readOnly: true
            - name: catalog-feed-spool
              mountPath: /var/spool/catalog-feeds
            {{- if $ctx.Values.licensing.reports.persistence.enabled }}
            - name: license-reports
              mountPath: {{ $ctx.Values.licensing.reports.dir }}
            {{- end }}
            {{- end }}
            {{- with $svc.extraVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          livenessProbe:
            httpGet: { path: /health, port: 8080 }
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet: { path: /health, port: 8080 }
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: tmp
          emptyDir: {}
        - name: license
          secret:
            secretName: {{ include "vistaplatform.licenseSecretName" $ctx }}
            # Optional so a Core deployment needs no entitlement token at all:
            # without this, every pod would block in ContainerCreating waiting
            # for a Secret that an unlicensed install has no reason to create.
            # Enterprise deployments still supply it; only admin-service reads
            # it (ee/edition), and it grants rather than gates.
            optional: true
            items:
              - key: {{ $ctx.Values.license.secretKey }}
                path: {{ $ctx.Values.license.secretKey }}
        {{- if $ctx.Values.serviceMtls.enabled }}
        - name: mtls
          secret:
            secretName: {{ $name }}-mtls
        {{- end }}
        {{- if and $ctx.Values.jwtSigning.enabled (has $name (list "auth-service" "admin-service")) }}
        - name: jwt-signing
          secret:
            secretName: {{ include "vistaplatform.fullname" $ctx }}-jwt-signing
            defaultMode: 0400
        {{- end }}
        {{- if eq $name "admin-service" }}
        {{/*
          Only the signing key is projected — not install-id, which reaches
          admin-service as INSTALL_ID above.
        */}}
        - name: install-signing
          secret:
            secretName: {{ include "vistaplatform.installSecretName" $ctx }}
            defaultMode: 0400
            items:
              - key: signing-key.pem
                path: signing-key.pem
        {{- $spool := (($ctx.Values.catalogFeeds | default dict).spool | default dict) }}
        - name: catalog-feed-spool
          emptyDir:
            sizeLimit: {{ $spool.sizeLimit | default "3Gi" | quote }}
        {{- if $ctx.Values.licensing.reports.persistence.enabled }}
        - name: license-reports
          persistentVolumeClaim:
            claimName: {{ include "vistaplatform.licenseReportsClaimName" $ctx }}
        {{- end }}
        {{- end }}
        {{- with $svc.extraVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ $name }}
  labels:
    {{- include "vistaplatform.labels" $ctx | nindent 4 }}
    app.kubernetes.io/component: {{ $name }}
spec:
  selector:
    {{- include "vistaplatform.selectorLabels" (dict "ctx" $ctx "component" $name) | nindent 4 }}
  ports:
    - name: http
      port: 8080
      targetPort: 8080
    {{- if $ctx.Values.serviceMtls.enabled }}
    - name: https-mtls
      port: 8443
      targetPort: 8443
    {{- end }}
    {{- if and $ctx.Values.agentMtls.enabled (hasKey $ctx.Values.agentMtls.backends $name) }}
    - name: agent-mtls
      port: {{ $ctx.Values.agentMtls.port }}
      targetPort: {{ $ctx.Values.agentMtls.port }}
    {{- end }}
{{- if gt (int $replicas) 1 }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ $name }}
  labels:
    {{- include "vistaplatform.labels" $ctx | nindent 4 }}
    app.kubernetes.io/component: {{ $name }}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      {{- include "vistaplatform.selectorLabels" (dict "ctx" $ctx "component" $name) | nindent 6 }}
{{- end }}
{{- end -}}
