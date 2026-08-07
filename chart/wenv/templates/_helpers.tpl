{{- define "wenv.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "wenv.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "wenv.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "wenv.labels" -}}
app.kubernetes.io/name: {{ include "wenv.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}
