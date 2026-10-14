{{/*
vistaplatform.maintenanceChartSource — the OCI chart repository an in-product
update installs from: maintenance.chartSource when set, otherwise
oci://<image.registry>/<image.repoPrefix>/vistaplatform, the registry the
images already come from (so a mirrored install updates from its mirror).
*/}}
{{- define "vistaplatform.maintenanceChartSource" -}}
{{- $m := .Values.maintenance | default dict -}}
{{- if $m.chartSource -}}
{{- $m.chartSource -}}
{{- else -}}
{{- printf "oci://%s/%s/vistaplatform" .Values.image.registry .Values.image.repoPrefix -}}
{{- end -}}
{{- end -}}

{{/* Name of the backups claim. */}}
{{- define "vistaplatform.maintenanceBackupsClaimName" -}}
maintenance-backups
{{- end -}}
