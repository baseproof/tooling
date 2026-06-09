{{/*
=============================================================================
templates/_helpers.tpl — shared name/label snippets (stock Helm convention).

Database-secret helpers resolve the existingSecret-or-inline-url choice once
and feed the deployment.
=============================================================================
*/}}

{{- define "auditor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "auditor.fullname" -}}
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

{{- define "auditor.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "auditor.labels" -}}
helm.sh/chart: {{ include "auditor.chart" . }}
{{ include "auditor.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: auditor
app.kubernetes.io/part-of: baseproof
{{- end -}}

{{- define "auditor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auditor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "auditor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "auditor.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
External-database Secret resolution.

database.existingSecret takes precedence; otherwise the chart writes its own
Secret "<fullname>-db" populated from database.url. The required check in
auditor.validateDatabase trips when neither is supplied.
*/}}
{{- define "auditor.externalDbSecretName" -}}
{{- if .Values.database.existingSecret -}}
{{- .Values.database.existingSecret -}}
{{- else -}}
{{- printf "%s-db" (include "auditor.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Bitnami-postgresql Secret resolution (postgresql.enabled — in-cluster Postgres
via the sub-chart, mirroring the ledger chart). When
postgresql.auth.existingSecret is set, the operator's Secret is the source of
truth; otherwise bitnami creates "<release>-postgresql".
*/}}
{{- define "auditor.bitnamiSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret -}}
{{- .Values.postgresql.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgresql" .Release.Name -}}
{{- end -}}
{{- end -}}

{{- define "auditor.bitnamiPasswordKey" -}}
{{- default "password" .Values.postgresql.auth.secretKeys.userPasswordKey -}}
{{- end -}}

{{/*
Validate database mode at template time. Exactly one path must be configured:
postgresql.enabled (in-cluster via Helm), database.existingSecret (existing
endpoint), or database.url (inline dev DSN). Catches "forgot to set anything"
before the pod boots and crash-loops on a missing AUDITOR_GOSSIP_DSN.
*/}}
{{- define "auditor.validateDatabase" -}}
{{- if not .Values.postgresql.enabled -}}
{{- if and (not .Values.database.existingSecret) (not .Values.database.url) -}}
{{- fail "auditor: configure exactly one of postgresql.enabled=true, database.existingSecret, or database.url (the gossip DSN, AUDITOR_GOSSIP_DSN)" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate the required injected inputs at template time, so a misconfigured
release fails on `helm install` rather than CrashLooping on a missing doc.
*/}}
{{- define "auditor.validate" -}}
{{- if not .Values.bootstrap.existingSecret -}}
{{- fail "auditor: bootstrap.existingSecret is required (the network BootstrapDocument, mounted at /etc/auditor/bootstrap.json)" -}}
{{- end -}}
{{- end -}}
