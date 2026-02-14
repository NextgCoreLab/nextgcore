{{/*
Common labels
*/}}
{{- define "nextgcore.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nextgcore
{{- end }}

{{/*
NF labels
*/}}
{{- define "nextgcore.nfLabels" -}}
{{ include "nextgcore.labels" . }}
app.kubernetes.io/name: {{ .nfName }}
app.kubernetes.io/instance: {{ .Release.Name }}-{{ .nfName }}
app.kubernetes.io/component: {{ .nfComponent | default "control-plane" }}
{{- end }}

{{/*
NF image reference
*/}}
{{- define "nextgcore.image" -}}
{{- if .global.image.registry -}}
{{ .global.image.registry }}/{{ .nf.image.repository }}:{{ .nf.image.tag }}
{{- else -}}
{{ .nf.image.repository }}:{{ .nf.image.tag }}
{{- end -}}
{{- end }}
