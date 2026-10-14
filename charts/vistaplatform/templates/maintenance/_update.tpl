{{/*
One-click update and rollback (spec platform-maintenance.md §3 "Update", WP4):
helpers shared by the update-Job ConfigMap and maintenance-service's
Deployment.
*/}}

{{/* Name of the ConfigMap holding the update / rollback Job template. */}}
{{- define "vistaplatform.maintenanceUpdateJobConfigMapName" -}}
{{- printf "%s-maintenance-update-job" (include "vistaplatform.fullname" .) -}}
{{- end -}}

{{/* Where maintenance-service mounts it. */}}
{{- define "vistaplatform.maintenanceUpdateJobMountPath" -}}
/etc/vistaplatform/maintenance-update-job
{{- end -}}

{{/* maintenance.updates.timeout — the helm --timeout of an update or rollback. */}}
{{- define "vistaplatform.maintenanceUpdateTimeout" -}}
{{- $m := .Values.maintenance | default dict -}}
{{- $u := $m.updates | default dict -}}
{{- $u.timeout | default "30m" -}}
{{- end -}}

{{/*
The Job's activeDeadlineSeconds: the helm timeout plus ten minutes for the
chart pull, the release read and the pod's own start, so helm reports its
timeout before Kubernetes kills the pod. The timeout must be a whole number of
s, m or h — Helm accepts more (1h30m), but this deadline is computed here.
*/}}
{{- define "vistaplatform.maintenanceUpdateDeadlineSeconds" -}}
{{- $t := include "vistaplatform.maintenanceUpdateTimeout" . -}}
{{- if not (regexMatch "^[1-9][0-9]*[smh]$" $t) -}}
{{- fail (printf "maintenance.updates.timeout=%q must be a whole number of seconds, minutes or hours, like 30m or 1h" $t) -}}
{{- end -}}
{{- $n := atoi (trimSuffix "s" (trimSuffix "m" (trimSuffix "h" $t))) -}}
{{- $mult := 1 -}}
{{- if hasSuffix "m" $t }}{{ $mult = 60 }}{{ end -}}
{{- if hasSuffix "h" $t }}{{ $mult = 3600 }}{{ end -}}
{{- add (mul $n $mult) 600 -}}
{{- end -}}

{{/* "true" when maintenance.updates.<key> is literally true. */}}
{{- define "vistaplatform.maintenanceUpdatesFlag" -}}
{{- $m := .ctx.Values.maintenance | default dict -}}
{{- $u := $m.updates | default dict -}}
{{- ternary "true" "false" (eq (toString (index $u .key)) "true") -}}
{{- end -}}
