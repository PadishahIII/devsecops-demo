{{/*
Common helpers for the notes-app chart.
*/}}

{{/* The app name is fixed (the Service selector and in-cluster DNS name
    notes.<ns>.svc.cluster.local depend on it). */}}
{{- define "notes-app.name" -}}
notes
{{- end }}

{{/*
The full image reference. Digest-pinned when .Values.image.digest is set
(build once, promote the same digest); otherwise repository:tag for local/dev.
*/}}
{{- define "notes-app.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default "latest" }}
{{- end -}}
{{- end }}

{{/*
Common labels applied to every object. The `pipeline: cd-<n>` label is only
added when a build number is present so local renders stay clean.
*/}}
{{- define "notes-app.labels" -}}
app: {{ include "notes-app.name" . }}
environment: {{ .Values.environment }}
app.kubernetes.io/name: {{ include "notes-app.name" . }}
app.kubernetes.io/part-of: devsecops-demo
{{- if .Values.buildNumber }}
app.kubernetes.io/pipeline: cd-{{ .Values.buildNumber }}
{{- end }}
{{- end }}
