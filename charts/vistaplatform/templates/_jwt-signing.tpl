{{/*
JWT signing helpers (#584): when may verifier services stop accepting HS256?

jwtSigning.acceptLegacyHmac decides whether the legacy shared secret
(JWT_SECRET) is still injected into the ~15 services that only VERIFY tokens.
While it is, any one of them can forge a token for any user, tenant or role, so
the ES256 migration is not finished until it is off. It used to be a manual
step ("set it to false one refresh-token lifetime after enabling") that nobody
was reminded to take. "auto" (the default) takes it on the first helm upgrade
after it is safe.

Why "safe" is decidable from the signing Secret alone: HS256 tokens are minted
only while no signing key is mounted, i.e. before the Secret below existed. So
the Secret's age is the time since the cutover, and once it exceeds the
longest-lived token (the refresh-token lifetime plus margin,
jwtSigning.legacyHmacWindowHours) no HS256 token can still be valid.

The decision, in order:

  enabled=false                  -> ON   HS256 is the only scheme.
  true / false                   -> as pinned.
  auto, no live cluster          -> ON   see "Offline" below.
  auto, Secret absent, install   -> OFF  fresh install: ES256 from token one.
  auto, Secret absent, upgrade   -> ON   signing starts with THIS upgrade, so
                                         every live session is still HS256.
  auto, Secret marked at install -> OFF  (annotation below) no HS256 session
                                         ever existed on this release.
  auto, Secret age >= window     -> OFF
  auto, Secret age <  window     -> ON
  auto, creationTimestamp unreadable -> ON

Offline. `lookup` returns empty for EVERYTHING under `helm template`, client
`--dry-run`, and renderers built on them (Argo CD). Read naively that is
"Secret absent", which on an install-shaped render means OFF — closing the
window for a GitOps user in the middle of a migration. So the same kube-system
companion probe the TLS and cert-manager checks use (_helpers.tpl) separates
"no cluster" from "no Secret", and offline renders keep acceptance ON, which is
exactly the behaviour before "auto" existed. GitOps users pin the value
explicitly; values.yaml and the Core secrets guide say so.

Why the install marker: on a fresh install the Secret is created at the same
moment as the release, so a later upgrade inside the window would otherwise see
a young Secret and turn acceptance back ON for a week on a release that never
issued an HS256 token. The marker is stamped only when a live install creates
the Secret, and preserved verbatim afterwards (secrets-jwt-signing.yaml).

The fact-gathering (`vistaplatform.jwtLegacyHmacFacts`) is the only part that
talks to the cluster and is kept separate on purpose:
scripts/test-chart-jwt-signing.mjs swaps it for a stub in a scratch copy of the
chart, which lets every row above be rendered end to end through the real
deployment template.
*/}}

{{- define "vistaplatform.jwtSigningSecretName" -}}
{{- printf "%s-jwt-signing" (include "vistaplatform.fullname" .) -}}
{{- end -}}

{{/* Annotation stamped on the signing Secret when a live INSTALL creates it. */}}
{{- define "vistaplatform.jwtLegacyHmacMarkerKey" -}}
vistaplatform.io/legacy-hmac-sessions
{{- end -}}

{{/* Cluster facts, as JSON. BEGIN-FACTS (the test stubs out this define). */}}
{{- define "vistaplatform.jwtLegacyHmacFacts" -}}
{{- $live := lookup "v1" "Namespace" "" "kube-system" -}}
{{- $sec := lookup "v1" "Secret" .Release.Namespace (include "vistaplatform.jwtSigningSecretName" .) -}}
{{- $meta := dict -}}
{{- if $sec -}}
{{- $meta = $sec.metadata | default dict -}}
{{- end -}}
{{- $annotations := $meta.annotations | default dict -}}
{{- toJson (dict
      "live" (not (empty $live))
      "found" (not (empty $sec))
      "created" ($meta.creationTimestamp | default "" | toString)
      "marker" (index $annotations (include "vistaplatform.jwtLegacyHmacMarkerKey" .) | default "")) -}}
{{- end -}}
{{/* END-FACTS */}}

{{/*
The decision, as JSON: {"accept": bool, "reason": string}. Consumed by
backend/_deployment.tpl (whether verifiers get JWT_SECRET) and NOTES.txt (which
mode was chosen and why).
*/}}
{{- define "vistaplatform.jwtLegacyHmac" -}}
{{- /* default dict: --reuse-values from a release older than jwtSigning. */ -}}
{{- $cfg := .Values.jwtSigning | default dict -}}
{{- $setting := $cfg.acceptLegacyHmac -}}
{{- $s := "" -}}
{{- if kindIs "bool" $setting -}}
{{- $s = ternary "true" "false" $setting -}}
{{- else if kindIs "invalid" $setting -}}
{{- $s = "auto" -}}
{{- else -}}
{{- $s = toString $setting | lower -}}
{{- end -}}
{{- $accept := true -}}
{{- $reason := "" -}}
{{- if not $cfg.enabled -}}
{{- $reason = "jwtSigning.enabled=false, so HS256 with the shared secret is the only signing scheme" -}}
{{- else if eq $s "true" -}}
{{- $reason = "pinned by jwtSigning.acceptLegacyHmac=true" -}}
{{- else if eq $s "false" -}}
{{- $accept = false -}}
{{- $reason = "pinned by jwtSigning.acceptLegacyHmac=false" -}}
{{- else if eq $s "auto" -}}
{{- $windowH := $cfg.legacyHmacWindowHours | default 192 | int64 -}}
{{- if le $windowH 0 -}}
{{- fail (printf "jwtSigning.legacyHmacWindowHours must be a positive number of hours (got %v)" $cfg.legacyHmacWindowHours) -}}
{{- end -}}
{{- $f := fromJson (include "vistaplatform.jwtLegacyHmacFacts" .) -}}
{{- if not $f.live -}}
{{- $reason = "auto: no cluster to inspect (helm template, client --dry-run or a GitOps renderer), so the legacy secret is kept; pin jwtSigning.acceptLegacyHmac if you deploy this way" -}}
{{- else if not $f.found -}}
{{- if .Release.IsUpgrade -}}
{{- $reason = "auto: ES256 signing starts with this upgrade, so sessions issued before it are HS256 and must keep verifying" -}}
{{- else -}}
{{- $accept = false -}}
{{- $reason = "auto: fresh install, every session is ES256 from the first token" -}}
{{- end -}}
{{- else if eq (toString $f.marker) "none" -}}
{{- $accept = false -}}
{{- $reason = "auto: the signing key was created at install, so no HS256 session has ever existed" -}}
{{- else -}}
{{- $created := toDate "2006-01-02T15:04:05Z07:00" (toString $f.created) -}}
{{- $createdS := unixEpoch $created | atoi | int64 -}}
{{- if le $createdS 0 -}}
{{- $reason = printf "auto: could not read the signing Secret's creationTimestamp (%q), so the legacy secret is kept" (toString $f.created) -}}
{{- else -}}
{{- $ageH := div (sub (now | unixEpoch | atoi | int64) $createdS) 3600 -}}
{{- if ge $ageH $windowH -}}
{{- $accept = false -}}
{{- $reason = printf "auto: ES256 signing has been on for %dh, past the %dh window in which an HS256 session could still be valid" $ageH $windowH -}}
{{- else -}}
{{- $reason = printf "auto: ES256 signing has been on for %dh; HS256 is accepted until it reaches %dh (the first helm upgrade after %s closes the window)" $ageH $windowH (dateInZone "2006-01-02 15:04 UTC" (dateModify (printf "%dh" $windowH) $created) "UTC") -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- fail (printf "jwtSigning.acceptLegacyHmac must be auto, true or false (got %q)" (toString $setting)) -}}
{{- end -}}
{{- toJson (dict "accept" $accept "reason" $reason) -}}
{{- end -}}
