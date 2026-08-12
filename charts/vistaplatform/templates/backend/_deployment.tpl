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
  */}}
  {{- with $svc.strategy }}
  strategy:
    type: {{ . }}
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
        v0.2.0 — wait for schema-migration Job to have populated the database
        before this backend's main container starts. Avoids the "backend
        crashloops on missing tables" cascade that breaks first-install with
        helm --wait.

        Polls Postgres for a sentinel table (public.tenants — fundamental to
        the data model, present from the very first schema apply). Loops
        forever until the table exists; if the schema-migration Job is
        failing for some reason, this init container will hang until the pod
        is killed by kubelet, which surfaces the failure to the operator.
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
              echo "Waiting for Postgres to be reachable..."
              {{- if $ctx.Values.datastores.postgres.enabled }}
              until pg_isready -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" >/dev/null 2>&1; do
                sleep 2
              done
              echo "Postgres up. Waiting for schema (sentinel: public.tenants)..."
              until psql -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='tenants'" 2>/dev/null | grep -q '^1$'; do
                sleep 3
              done
              {{- else }}
              until pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; do
                sleep 2
              done
              echo "Postgres up. Waiting for schema (sentinel: public.tenants)..."
              until psql "$DATABASE_URL" -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='tenants'" 2>/dev/null | grep -q '^1$'; do
                sleep 3
              done
              {{- end }}
              echo "Schema ready."
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
            {{- with $svc.extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
            {{/*
            Synthetic-edge checks: monitoring-service consumes a JSON-encoded
            list via SYNTHETIC_CHECKS_JSON. Sourced from .Values.monitoring.
            syntheticChecks so customers can declare checks in a structured
            YAML list without copying the other extraEnv defaults
            (NATS_MONITOR_URL etc.). See values.yaml `monitoring:` block.
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
