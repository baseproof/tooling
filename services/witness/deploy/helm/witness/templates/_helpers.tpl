{{/*
templates/_helpers.tpl — shared name/label snippets (stock Helm convention).
*/}}

{{- define "witness.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "witness.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "witness.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "witness.labels" -}}
helm.sh/chart: {{ include "witness.chart" . }}
{{ include "witness.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: witness
app.kubernetes.io/part-of: baseproof
{{- end -}}

{{- define "witness.selectorLabels" -}}
app.kubernetes.io/name: {{ include "witness.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "witness.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "witness.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Validate the required injected inputs at template time, so a misconfigured
release fails on `helm install` rather than CrashLooping on a missing key/doc.
*/}}
{{- define "witness.validate" -}}
{{- if not .Values.signingKey.existingSecret -}}
{{- fail "witness: signingKey.existingSecret is required (the cosign key Secret, mounted at /etc/witness/keys)" -}}
{{- end -}}
{{- if not .Values.bootstrap.existingSecret -}}
{{- fail "witness: bootstrap.existingSecret is required (the network BootstrapDocument, mounted at /etc/witness/bootstrap.json)" -}}
{{- end -}}
{{- end -}}
