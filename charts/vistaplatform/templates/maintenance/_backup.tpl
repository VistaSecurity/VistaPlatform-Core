{{/*
Platform backups (spec platform-maintenance.md §3 "Backup", WP3): helpers
shared by the backup Job-template ConfigMap, maintenance-service's Deployment
and the egress policy.
*/}}

{{/* "true" when the chart renders backup storage: maintenance on, backups on. */}}
{{- define "vistaplatform.maintenanceBackupsEnabled" -}}
{{- $m := .Values.maintenance | default dict -}}
{{- $b := $m.backups | default dict -}}
{{- if and (include "vistaplatform.maintenanceEnabled" .) (eq (toString $b.enabled) "true") -}}
true
{{- end -}}
{{- end -}}

{{/* The backups volume's access mode (maintenance.backups.accessMode). */}}
{{- define "vistaplatform.maintenanceBackupsAccessMode" -}}
{{- $m := .Values.maintenance | default dict -}}
{{- $b := $m.backups | default dict -}}
{{- $b.accessMode | default "ReadWriteOnce" -}}
{{- end -}}

{{/* Name of the ConfigMap holding the backup Job template. */}}
{{- define "vistaplatform.maintenanceJobsConfigMapName" -}}
{{- printf "%s-maintenance-jobs" (include "vistaplatform.fullname" .) -}}
{{- end -}}

{{/* Where maintenance-service mounts the backups volume and the Job template. */}}
{{- define "vistaplatform.maintenanceBackupsMountPath" -}}
/var/lib/vistaplatform/backups
{{- end -}}
{{- define "vistaplatform.maintenanceJobsMountPath" -}}
/etc/vistaplatform/maintenance-jobs
{{- end -}}
