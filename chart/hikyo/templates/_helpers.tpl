{{- define "hikyo.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hikyo.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "hikyo.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hikyo.labels" -}}
app.kubernetes.io/name: {{ include "hikyo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}
