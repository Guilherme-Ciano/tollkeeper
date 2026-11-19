{{- define "tollkeeper.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tollkeeper.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tollkeeper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tollkeeper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tollkeeper.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "tollkeeper.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tollkeeper.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}:{{ $tag }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
{{- end -}}

{{- define "tollkeeper.config" -}}
{{- $base := dict
  "server" (dict "listen" "0.0.0.0:8080" "admin_listen" "0.0.0.0:9090" "public_url" .Values.publicURL "shutdown_drain_delay" "5s")
  "audit" (dict "path" "/var/lib/tollkeeper/audit/audit.jsonl" "chain_id" "${POD_NAME}")
-}}
{{- if .Values.auditSigningKey.secretName -}}
{{- $_ := set $base.audit "checkpoint" (dict "signing_key_file" (printf "/var/lib/tollkeeper/keys/%s" .Values.auditSigningKey.key)) -}}
{{- end -}}
{{- if .Values.requestStateKey.secretName -}}
{{- $_ := set $base.server "request_state_key_file" (printf "/var/lib/tollkeeper/state/%s" .Values.requestStateKey.key) -}}
{{- end -}}
{{- if .Values.redis.enabled -}}
{{- $_ := set $base "rate_limits" (dict "store" "redis" "redis" (dict "addrs" .Values.redis.addrs "key_prefix" .Values.redis.keyPrefix)) -}}
{{- end -}}
{{- $merged := mustMergeOverwrite $base (deepCopy .Values.config) -}}
{{- toYaml $merged -}}
{{- end -}}
