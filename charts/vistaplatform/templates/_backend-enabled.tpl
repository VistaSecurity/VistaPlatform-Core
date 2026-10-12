{{/*
vistaplatform.backendEnabled — "true" when backend <name> should render, ""
when the operator set backends.<name>.enabled=false. Absent key = enabled.

Called as: include "vistaplatform.backendEnabled" (dict "root" $ "name" $name)

Deliberately NOT `$svc.enabled | default true`: `default` treats a bool false
as empty and returns true, so an explicit false would never disable anything.
*/}}
{{- define "vistaplatform.backendEnabled" -}}
{{- $svc := index .root.Values.backends .name | default dict -}}
{{- if and (hasKey $svc "enabled") (eq (toString (get $svc "enabled")) "false") -}}
{{- else -}}
true
{{- end -}}
{{- end -}}
