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

{{- define "hikyo.operator.fullname" -}}
{{- printf "%s-operator" (include "hikyo.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "hikyo.operator.validate" -}}
{{- if not (hasKey .Values "operator") -}}
  {{- fail "operator values are required" -}}
{{- end -}}
{{- if not (hasKey .Values.operator "enabled") -}}
  {{- fail "operator.enabled is required" -}}
{{- end -}}
{{- if .Values.operator.enabled -}}
  {{- if not (hasKey .Values.operator "namespaces") -}}
    {{- fail "operator.namespaces is required; use [] explicitly for cluster-wide authority" -}}
  {{- end -}}
  {{- if not (kindIs "slice" .Values.operator.namespaces) -}}
    {{- fail "operator.namespaces must be a list" -}}
  {{- end -}}
  {{- if ne (len .Values.operator.namespaces) (len (uniq .Values.operator.namespaces)) -}}
    {{- fail "operator.namespaces must not contain duplicates" -}}
  {{- end -}}
  {{- range .Values.operator.namespaces -}}
    {{- if empty . -}}
      {{- fail "operator.namespaces entries must not be empty" -}}
    {{- end -}}
  {{- end -}}
  {{- if not (hasKey .Values.operator "triggerRollouts") -}}
    {{- fail "operator.triggerRollouts is required" -}}
  {{- end -}}
  {{- if not (hasKey .Values.operator "designatedServiceAccounts") -}}
    {{- fail "operator.designatedServiceAccounts is required" -}}
  {{- end -}}
  {{- if not (kindIs "map" .Values.operator.designatedServiceAccounts) -}}
    {{- fail "operator.designatedServiceAccounts must be a map" -}}
  {{- end -}}
  {{- range $namespace, $serviceAccounts := .Values.operator.designatedServiceAccounts -}}
    {{- if not (kindIs "slice" $serviceAccounts) -}}
      {{- fail (printf "operator.designatedServiceAccounts[%s] must be a list" $namespace) -}}
    {{- end -}}
    {{- range $serviceAccounts -}}
      {{- if empty . -}}
        {{- fail (printf "operator.designatedServiceAccounts[%s] entries must not be empty" $namespace) -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- $resources := required "operator.resources is required" .Values.operator.resources -}}
  {{- $requests := required "operator.resources.requests is required" .Values.operator.resources.requests -}}
  {{- $limits := required "operator.resources.limits is required" .Values.operator.resources.limits -}}
  {{- $requestCPU := required "operator.resources.requests.cpu is required" .Values.operator.resources.requests.cpu -}}
  {{- $requestMemory := required "operator.resources.requests.memory is required" .Values.operator.resources.requests.memory -}}
  {{- $limitCPU := required "operator.resources.limits.cpu is required" .Values.operator.resources.limits.cpu -}}
  {{- $limitMemory := required "operator.resources.limits.memory is required" .Values.operator.resources.limits.memory -}}
  {{- $replicaCount := required "operator.replicaCount is required" .Values.operator.replicaCount -}}
  {{- if not (hasKey .Values.operator "leaderElection") -}}
    {{- fail "operator.leaderElection is required" -}}
  {{- end -}}
  {{- if not .Values.operator.leaderElection -}}
    {{- fail "operator.leaderElection must be true" -}}
  {{- end -}}
  {{- $stampRootSecretName := required "operator.stampRootSecretName is required" .Values.operator.stampRootSecretName -}}
{{- end -}}
{{- end -}}
