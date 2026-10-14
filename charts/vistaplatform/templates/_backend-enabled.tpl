{{/*
vistaplatform.backendEnabled — "true" when backend <name> should render, ""
when the operator set backends.<name>.enabled=false. Absent key = enabled.

maintenance-service additionally follows maintenance.enabled: the switch that
removes the whole maintenance component (its RBAC and backups volume, in
templates/maintenance/) removes the backend with it, so every loop over
.Values.backends — Deployments, Services, mTLS Certificates, NetworkPolicy
rules, IngressRoutes — drops it from this one place.

Called as: include "vistaplatform.backendEnabled" (dict "root" $ "name" $name)

Deliberately NOT `$svc.enabled | default true`: `default` treats a bool false
as empty and returns true, so an explicit false would never disable anything.
*/}}
{{- define "vistaplatform.backendEnabled" -}}
{{- $svc := index .root.Values.backends .name | default dict -}}
{{- if and (hasKey $svc "enabled") (eq (toString (get $svc "enabled")) "false") -}}
{{- else if and (eq .name "maintenance-service") (not (include "vistaplatform.maintenanceEnabled" .root)) -}}
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
vistaplatform.maintenanceEnabled — "true" unless maintenance.enabled is
explicitly false (absent block = enabled, the chart default). Same bool-false
care as above.
*/}}
{{- define "vistaplatform.maintenanceEnabled" -}}
{{- $m := .Values.maintenance | default dict -}}
{{- if and (hasKey $m "enabled") (eq (toString (get $m "enabled")) "false") -}}
{{- else -}}
true
{{- end -}}
{{- end -}}
