{{/* Common name helpers. */}}
{{- define "vistaplatform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vistaplatform.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vistaplatform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every resource. */}}
{{- define "vistaplatform.labels" -}}
helm.sh/chart: {{ include "vistaplatform.chart" . }}
app.kubernetes.io/name: {{ include "vistaplatform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vistaplatform
{{- end -}}

{{/* Selector labels for a given component. Usage: include "vistaplatform.selectorLabels" (dict "ctx" . "component" "auth-service") */}}
{{- define "vistaplatform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vistaplatform.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Fully-qualified image reference. Usage: include "vistaplatform.image" (dict "ctx" . "repo" "auth-service" "tag" "...") */}}
{{- define "vistaplatform.image" -}}
{{- $registry := .ctx.Values.image.registry -}}
{{- $prefix := .ctx.Values.image.repoPrefix -}}
{{- $tag := default (default .ctx.Chart.AppVersion .ctx.Values.image.tag) .tag -}}
{{- if .digest -}}
{{- printf "%s/%s/%s@%s" $registry $prefix .repo .digest -}}
{{- else -}}
{{- printf "%s/%s/%s:%s" $registry $prefix .repo $tag -}}
{{- end -}}
{{- end -}}

{{/* Pod-level securityContext. */}}
{{- define "vistaplatform.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext -}}
{{- end -}}

{{/* Per-component podAntiAffinity that prefers spreading replicas across nodes.
   Usage: include "vistaplatform.podAntiAffinity" (dict "ctx" . "component" "auth-service")
   Only emits content when .Values.enableSpreadAcrossNodes is true. */}}
{{- define "vistaplatform.podAntiAffinity" -}}
{{- if .ctx.Values.enableSpreadAcrossNodes -}}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
            app.kubernetes.io/name: {{ include "vistaplatform.name" .ctx }}
            app.kubernetes.io/instance: {{ .ctx.Release.Name }}
            app.kubernetes.io/component: {{ .component }}
{{- end -}}
{{- end -}}

{{/* Container-level securityContext. */}}
{{- define "vistaplatform.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext -}}
{{- end -}}

{{/* Name of the chart-managed Secret holding generated datastore creds. */}}
{{- define "vistaplatform.generatedSecretName" -}}
{{- printf "%s-generated" (include "vistaplatform.fullname" .) -}}
{{- end -}}

{{/* Name of the customer-supplied platform Secret. */}}
{{- define "vistaplatform.platformSecretName" -}}
{{- if .Values.platform.existingSecretName -}}
{{- .Values.platform.existingSecretName -}}
{{- else -}}
{{- printf "%s-platform" (include "vistaplatform.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Public tenant host used by ingress, runtime config, cookies, and notes. */}}
{{- define "vistaplatform.publicHost" -}}
{{- default "vista.local" .Values.tls.dnsName -}}
{{- end -}}

{{/* Name of the customer-applied license Secret. */}}
{{- define "vistaplatform.licenseSecretName" -}}
{{- .Values.license.existingSecretName -}}
{{- end -}}

{{/* Name of the customer-supplied billing (Stripe) Secret. */}}
{{- define "vistaplatform.billingSecretName" -}}
{{- if .Values.billing.stripe.existingSecretName -}}
{{- .Values.billing.stripe.existingSecretName -}}
{{- else -}}
{{- printf "%s-billing" (include "vistaplatform.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
True when any Stripe credential source is configured — either
billing.stripe.existingSecretName is set, or all three inline values are
provided. Used by _deployment.tpl to decide whether to inject STRIPE_*
env vars into admin-service. When false, billing is intentionally
disabled and admin-service falls back to config.go defaults.
*/}}
{{- define "vistaplatform.billingEnabled" -}}
{{- if .Values.billing.stripe.existingSecretName -}}
true
{{- else if and .Values.billing.stripe.secretKey .Values.billing.stripe.publishableKey .Values.billing.stripe.webhookSecret -}}
true
{{- end -}}
{{- end -}}

{{/* Validate TLS mode at template time. */}}
{{- define "vistaplatform.validateTLS" -}}
{{- $mode := .Values.tls.mode -}}
{{- if eq $mode "none" -}}
{{- if not .Values.tls.allowNone -}}
{{- fail "tls.mode=none requires tls.allowNone=true (intended for dev only)" -}}
{{- end -}}
{{- else if eq $mode "certManager" -}}
{{- if not .Values.tls.dnsName -}}{{- fail "tls.dnsName is required when tls.mode=certManager" -}}{{- end -}}
{{- if not .Values.tls.issuerRef.name -}}{{- fail "tls.issuerRef.name is required when tls.mode=certManager" -}}{{- end -}}
{{- else if eq $mode "selfSigned" -}}
{{/* Nothing required: dnsName defaults, and the cert is generated in-chart. */}}
{{- else if eq $mode "existingSecret" -}}
{{- if not .Values.tls.dnsName -}}{{- fail "tls.dnsName is required when tls.mode=existingSecret" -}}{{- end -}}
{{- if not .Values.tls.existingSecretName -}}{{- fail "tls.existingSecretName is required when tls.mode=existingSecret" -}}{{- end -}}
{{/* The named Secret must actually EXIST, and carry a certificate.

     Checking only that the NAME is non-empty is not a check. An IngressRoute
     pointing at an absent Secret does not fail: Traefik falls back to its own
     generated default certificate (CN=<hash>.traefik.default) and serves it.
     So `helm install --wait` returns success, every pod goes Ready, and every
     health check is green — while every TLS client fails with a hostname
     mismatch against a cert nobody configured. That is the silent-success
     shape this repo keeps paying for, and it is reachable by an ordinary
     bring-your-own-cert operator who applies values before creating the
     Secret, or who mistypes its name.

     Live-cluster only, using the same offline-detection as the cert-manager
     probe below: `lookup` returns empty for EVERYTHING during `helm template`
     and `--dry-run`, so a companion probe on kube-system distinguishes "no
     cluster" from "genuinely missing". kube-system rather than the release
     namespace, because on `--create-namespace` the release namespace does not
     exist yet.

     Note the interaction that follows from this: `helm install
     --create-namespace` with tls.mode=existingSecret cannot be satisfied — the
     Secret would have to live in a namespace that does not exist yet. Failing
     is correct, and the message says what to do instead. */}}
{{- if or .Release.IsInstall .Release.IsUpgrade -}}
{{- $live := lookup "v1" "Namespace" "" "kube-system" -}}
{{- if $live -}}
{{- $tlsSecret := lookup "v1" "Secret" .Release.Namespace .Values.tls.existingSecretName -}}
{{- if not $tlsSecret -}}
{{- fail (printf "tls.mode=existingSecret names Secret %q in namespace %q, but no such Secret exists. Traefik would silently serve its own default certificate instead, so the install would report success while every client failed on a hostname mismatch. Create the Secret first (kubectl -n %s create secret tls %s --cert=fullchain.crt --key=tls.key), then install. If the namespace does not exist yet, create it before the Secret rather than using --create-namespace. To have cert-manager issue and renew the certificate for you instead, use tls.mode=certManager with tls.issuerRef.name." .Values.tls.existingSecretName .Release.Namespace .Release.Namespace .Values.tls.existingSecretName) -}}
{{- end -}}
{{- if and $tlsSecret $tlsSecret.data -}}
{{- if not (index $tlsSecret.data "tls.crt") -}}
{{- fail (printf "tls.mode=existingSecret names Secret %q in namespace %q, but it has no tls.crt key (found: %s). Traefik cannot serve a certificate from it and would fall back to its own default. Recreate it as a TLS Secret: kubectl -n %s create secret tls %s --cert=fullchain.crt --key=tls.key" .Values.tls.existingSecretName .Release.Namespace (keys $tlsSecret.data | sortAlpha | join ", ") .Release.Namespace .Values.tls.existingSecretName) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- fail (printf "tls.mode must be one of: certManager, existingSecret, selfSigned, none (got %q)" $mode) -}}
{{- end -}}
{{- end -}}

{{/* Validate internal-transport mTLS config + prerequisites (#965).

Two classes of check:

  1. Coupling (pure render-time, always runs — including `helm template` and
     `helm lint`): the two datastore TLS toggles REQUIRE serviceMtls.enabled.
     Postgres/NATS TLS reuse the Platform-CA certs + the backends' /app/certs
     that only serviceMtls provisions, so a datastore toggle on while
     serviceMtls is off is an unrunnable config — fail loudly at render time.

  2. Cluster prerequisite (only fires on a real cluster-connected install/
     upgrade): serviceMtls needs cert-manager's CRDs present to issue the
     Platform CA + per-service certs. We probe with `lookup`, which returns
     empty during `helm template` / `helm install --dry-run` (no cluster) and
     real objects only when helm is talking to an actual apiserver. That keeps
     `helm template`, `helm lint`, and `make audit` green with the new
     defaults while still failing a genuine prereq-less `helm install` with a
     comprehensible message instead of a mysterious mid-apply CRD error.

Reloader is NOT hard-failed here — its absence doesn't break the install, it
breaks cert *rotation* ~60 days later, so NOTES.txt surfaces it as a loud
post-install reminder rather than an install-time gate. */}}
{{/* serviceRls coupling check (pure render-time, same class as (1) above).

serviceRls swaps each backend's DATABASE_URL onto the non-owner crypto_app role
so the tenant_isolation policies actually apply. Two things make that work, and
BOTH only exist for the bundled datastore:

  - schema.sql CREATEs crypto_app / crypto_bypass, but as NOLOGIN with no
    password. The rls-roles Job is what grants them LOGIN.
  - jobs/rls-roles.yaml renders only when datastores.postgres.enabled is true.

So with an external/managed Postgres the whole serviceRls block in
backend/_deployment.tpl is skipped (it is nested under postgres.enabled) and
DATABASE_URL comes from the database-url secret instead. The toggle reports
success and enforces nothing — precisely the silent no-op this repo keeps
relearning to hate. Fail loudly instead.

An external-Postgres operator who wants the role split has to do the deploy-layer
half themselves (ALTER ROLE crypto_app LOGIN PASSWORD ..., same for
crypto_bypass, then point database-url at crypto_app); until the chart can wire
that, the honest answer is to set serviceRls.enabled=false and enforce at the
database layer directly. */}}
{{- define "vistaplatform.validateRls" -}}
{{- if and .Values.serviceRls.enabled (not .Values.datastores.postgres.enabled) -}}
{{- fail "serviceRls.enabled=true requires datastores.postgres.enabled=true (the rls-roles Job that grants crypto_app/crypto_bypass LOGIN only renders for the bundled Postgres; with an external database the toggle would silently enforce nothing). Either use the bundled Postgres, or set serviceRls.enabled=false and grant the RLS roles on your managed instance yourself." -}}
{{- end -}}
{{- end -}}

{{- define "vistaplatform.validateMtls" -}}
{{- $pgTls := .Values.datastores.postgres.tls.enabled -}}
{{- $natsTls := .Values.datastores.nats.tls.enabled -}}
{{- if and $pgTls (not .Values.serviceMtls.enabled) -}}
{{- fail "datastores.postgres.tls.enabled=true requires serviceMtls.enabled=true (Postgres TLS reuses the Platform-CA client certs serviceMtls provisions). To turn encrypted internal transport OFF, set serviceMtls.enabled, datastores.postgres.tls.enabled and datastores.nats.tls.enabled all to false." -}}
{{- end -}}
{{- if and $natsTls (not .Values.serviceMtls.enabled) -}}
{{- fail "datastores.nats.tls.enabled=true requires serviceMtls.enabled=true (NATS mTLS reuses the per-service certs serviceMtls provisions). To turn encrypted internal transport OFF, set serviceMtls.enabled, datastores.postgres.tls.enabled and datastores.nats.tls.enabled all to false." -}}
{{- end -}}
{{- if .Values.agentMtls.enabled -}}
{{- if not .Values.serviceMtls.enabled -}}
{{- fail "agentMtls.enabled=true requires serviceMtls.enabled=true — the agent/sensor mTLS listener reuses the per-service mesh cert (Secret <svc>-mtls mounted at /app/certs). Enable serviceMtls first." -}}
{{- end -}}
{{/*
  Every configured agentMtls backend needs a dnsName. Without one,
  _deployment.tpl still sets AGENT_MTLS_REQUIRED and opens the port (it gates on
  hasKey, not on the value) while agent-passthrough.yaml renders NO
  IngressRouteTCP and no advertised URL — a silent, total agent lockout. Fail at
  install instead.

  Ranges the backends the operator actually configured rather than a hard-coded
  service list: someone enabling mTLS only for sensors should not be forced to
  invent a dnsName for device agents. values.yaml ships both keys with an empty
  dnsName and helm's deep-merge keeps them, so the empty-value check below is
  what does the real work in practice.
*/}}
{{- $agentBackends := .Values.agentMtls.backends | default dict -}}
{{/*
  The services that terminate agent/sensor mTLS. A hard-coded pair rather than a
  derived list on purpose: these are the only two backends with agent-facing
  endpoints, and _deployment.tpl gates BOTH of its env branches on
  `hasKey agentMtls.backends <name>`. So deleting a key here does not opt that
  service out — it emits no AGENT_MTLS_REQUIRED at all, the service falls back
  to its built-in default of true, and it then demands a client certificate with
  no IngressRouteTCP to carry one. Absence is the worst case, not the safe one,
  which is why it is checked rather than tolerated.
*/}}
{{- $agentFacing := list "device-interrogation-service" "sensor-manager" -}}
{{- $absent := list -}}
{{- range $svc := $agentFacing -}}
{{- if not (hasKey $agentBackends $svc) -}}
{{- $absent = append $absent $svc -}}
{{- end -}}
{{- end -}}
{{- if $absent -}}
{{- fail (printf "agentMtls.enabled=true but agentMtls.backends has no entry for: %s.\n\nRemoving a backend key does NOT opt it out of agent mTLS. The deployment template keys its AGENT_MTLS_REQUIRED env off the presence of that entry, so with the key gone the service emits no value, falls back to its built-in default of true, and demands a client certificate that no IngressRouteTCP exists to deliver — a silent, total lockout for that service's agents.\n\nKeep the entry and give it a dnsName, or set agentMtls.enabled=false to opt the whole platform out." (join ", " (sortAlpha $absent))) -}}
{{- end -}}
{{/*
  Every backend needs its OWN dnsName, not merely one between them. The two
  services share a passthrough entrypoint and are disambiguated by HostSNI, so a
  backend with no dnsName renders no IngressRouteTCP and no advertised URL while
  _deployment.tpl still sets AGENT_MTLS_REQUIRED=true and opens the port. The
  half-configured install is the dangerous one: it renders green and locks that
  service's agents out with no error to read.
*/}}
{{- $missing := list -}}
{{- range $svc, $cfg := $agentBackends -}}
{{- if not (and $cfg $cfg.dnsName) -}}
{{- $missing = append $missing $svc -}}
{{- end -}}
{{- end -}}
{{- if $missing -}}
{{- fail (printf "agentMtls.enabled is true (the DEFAULT since agent/sensor authentication became secure-by-default) but these agentMtls.backends entries have no dnsName: %s.\n\nAgent and sensor authentication is fail-closed: without a TLS-passthrough host, agents and sensors of that service cannot present their client certificate and every outbound call would 401. EVERY listed backend needs its own hostname — they share one passthrough entrypoint and are told apart by HostSNI, so one hostname cannot serve both.\n\nChoose one:\n  1. RECOMMENDED — set a passthrough hostname per backend:\n       --set agentMtls.backends.sensor-manager.dnsName=sensors.example.com \\\n       --set agentMtls.backends.device-interrogation-service.dnsName=agents.example.com\n     Each must be distinct, must differ from tls.dnsName (that host is terminated at the edge), and must resolve to a cluster-Traefik TLS-PASSTHROUGH entrypoint on port %v (the chart does not create that entrypoint). Existing agents/sensors must be re-enrolled or re-pointed at it.\n  2. EXPLICIT OPT-OUT — keep the previous, UNAUTHENTICATED behavior with\n       --set agentMtls.enabled=false\n     Agents and sensors then authenticate by their UUID alone; certificate rotation stays refused because it requires a client certificate in every mode.\n\nDev installs need none of this: docker compose sets AGENT_MTLS_REQUIRED=false for both services explicitly.\n\nMigration steps: docsv4/core/operate/security/service-mesh-mtls.md (Agent and sensor mTLS)." (join ", " (sortAlpha $missing)) .Values.agentMtls.port) -}}
{{- end -}}
{{- end -}}
{{- if .Values.serviceMtls.enabled -}}
{{/* Probe for cert-manager on a live cluster only (lookup is empty offline). */}}
{{- $cmCrd := lookup "apiextensions.k8s.io/v1" "CustomResourceDefinition" "" "certificates.cert-manager.io" -}}
{{- if and (not $cmCrd) (or .Release.IsInstall .Release.IsUpgrade) -}}
{{/* $cmCrd empty on a real cluster => cert-manager genuinely absent. It is
     also empty during `helm template`/dry-run, but there lookup returns
     empty for EVERYTHING, so a companion probe distinguishes the two. Probe
     kube-system rather than .Release.Namespace: kube-system exists on every
     real Kubernetes cluster from cluster bring-up, whereas the release
     namespace may not exist yet on a fresh `helm install --create-namespace`
     (the common first-install path, incl. the EKS production runbook) — that
     would make the release namespace probe empty on a genuinely live
     cluster too, silently skipping this check exactly when it matters most.
     kube-system is only ever absent when we're offline (template/dry-run). */}}
{{- $ns := lookup "v1" "Namespace" "" "kube-system" -}}
{{- if $ns -}}
{{- fail (printf "serviceMtls.enabled=true but cert-manager is not installed in this cluster (CRD certificates.cert-manager.io not found). Encrypted internal transport is ON by default (#965) and REQUIRES cert-manager v1.13+ (issues the Platform CA + per-service certs) and Stakater Reloader (restarts pods on cert rotation). Install both prerequisites, or opt out by setting serviceMtls.enabled, datastores.postgres.tls.enabled and datastores.nats.tls.enabled all to false. See docsv4/core/operate/deployment/rke2-v1/deployment-guide.md.") -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Cookie-secure flag derived from TLS mode. */}}
{{- define "vistaplatform.cookieSecure" -}}
{{- if eq .Values.tls.mode "none" -}}false{{- else -}}true{{- end -}}
{{- end -}}

{{/* Postgres URL.

v0.1.1: hardcoded sslmode=disable. Internal cluster traffic only — the
bundled postgres pod doesn't serve TLS yet, so requesting sslmode=require
or higher would fail the handshake.

Earlier versions of this helper coupled sslmode to .Values.tls.mode (the
API gateway's external TLS, which has nothing to do with internal
postgres-to-backend TLS). That coupling was a logic bug — disabling
external customer-facing TLS shouldn't be the trigger for disabling
internal database TLS, and vice versa. The two are unrelated concerns.

v0.1.2 introduces a dedicated datastores.postgres.tls block (mode +
caSecretName + clientCertSecretName) and configures the postgres pod
to serve TLS via cert-manager. Backends connect with sslmode=verify-full
+ per-backend client certs. See CHART-V0.1.2-MTLS-PLAN.md.

The role used in the connection string is parameterized by
"vistaplatform.databaseURLForUser" so the RLS role-split (serviceRls,
crypto_app / crypto_bypass) can reuse the exact same host / db / sslmode /
sslrootcert shape and vary ONLY the username — every other connection
property stays identical to the owner URL. "vistaplatform.databaseURL" keeps
its original single-arg signature (owner role from
datastores.postgres.user) so existing callers and OFF-toggle output are
byte-for-byte unchanged. */}}
{{- define "vistaplatform.databaseURLForUser" -}}
{{- $ctx := .ctx -}}
{{- $user := .user -}}
{{- if $ctx.Values.datastores.postgres.tls.enabled -}}
postgres://{{ $user }}:$(POSTGRES_PASSWORD)@postgres:5432/{{ $ctx.Values.datastores.postgres.db }}?sslmode=verify-full&sslrootcert=/app/certs/ca.crt
{{- else -}}
postgres://{{ $user }}:$(POSTGRES_PASSWORD)@postgres:5432/{{ $ctx.Values.datastores.postgres.db }}?sslmode=disable
{{- end -}}
{{- end -}}

{{- define "vistaplatform.databaseURL" -}}
{{- include "vistaplatform.databaseURLForUser" (dict "ctx" . "user" .Values.datastores.postgres.user) -}}
{{- end -}}

{{/* Redis URL pointing at the in-cluster Redis service. */}}
{{- define "vistaplatform.redisURL" -}}
redis://:$(REDIS_PASSWORD)@redis:6379/0
{{- end -}}

{{/*
Normalised generative-AI provider kind: "" when nothing is configured, so every
template can branch on one truthiness test. "none" is a real, selectable value
meaning the same as unset (ai.NewFromEnv treats them identically), and an
operator who writes it deliberately must get the same silence as one who left
the field blank.
*/}}
{{- define "vistaplatform.aiProvider" -}}
{{- $kind := trim (default "" .Values.ai.provider) -}}
{{- if or (eq $kind "") (eq (lower $kind) "none") -}}
{{- else -}}
{{- $kind -}}
{{- end -}}
{{- end -}}

{{/*
Name of the environment variable the provider reads its credential from.

The platform never holds a key in configuration — AI_API_KEY_ENV carries the
NAME of the variable and cfg.APIKey() resolves it at the moment of use, so a
rotated key is picked up by the next request and a leaked configuration row is a
configuration row. An operator who does not name one gets the provider's own
default, which is what shared/ai/config.go falls back to; spelling it out here
keeps the Secret's env var and AI_API_KEY_ENV from ever disagreeing.
*/}}
{{- define "vistaplatform.aiAPIKeyEnvVar" -}}
{{- $explicit := trim (default "" .Values.ai.apiKey.envVar) -}}
{{- if $explicit -}}
{{- $explicit -}}
{{- else if eq (include "vistaplatform.aiProvider" .) "openai_compat" -}}
OPENAI_API_KEY
{{- else -}}
ANTHROPIC_API_KEY
{{- end -}}
{{- end -}}
