{{/* Nom court de la chart. */}}
{{- define "vaultaire.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Nom complet : <release> ou <release>-vaultaire. */}}
{{- define "vaultaire.fullname" -}}
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

{{- define "vaultaire.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vaultaire.labels" -}}
helm.sh/chart: {{ include "vaultaire.chart" . }}
{{ include "vaultaire.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: vaultaire
{{- end -}}

{{- define "vaultaire.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultaire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: core
{{- end -}}

{{- define "vaultaire.mariadb.fullname" -}}
{{- printf "%s-mariadb" (include "vaultaire.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vaultaire.mariadb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultaire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: database
{{- end -}}

{{- define "vaultaire.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vaultaire.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Le Secret lu : celui fourni, ou celui que la chart crée. */}}
{{- define "vaultaire.secretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "vaultaire.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "vaultaire.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "vaultaire.mariadb.image" -}}
{{- $i := .Values.mariadb.image -}}
{{- if $i.digest -}}
{{- printf "%s:%s@%s" $i.repository $i.tag $i.digest -}}
{{- else -}}
{{- printf "%s:%s" $i.repository $i.tag -}}
{{- end -}}
{{- end -}}

{{- define "vaultaire.dbHost" -}}
{{- if .Values.database.host -}}
{{- .Values.database.host -}}
{{- else if .Values.mariadb.enabled -}}
{{- include "vaultaire.mariadb.fullname" . -}}
{{- else -}}
{{- fail "database.host est requis quand mariadb.enabled=false" -}}
{{- end -}}
{{- end -}}

{{/*
Ports du conteneur : au-dessus de 1024, aucun privilège. Le Service republie
les ports standard (389, 636, 443, 53).
*/}}
{{- define "vaultaire.containerPorts" -}}
ducky: 6666
web: 4443
api: 6643
ldap: 3389
ldaps: 3636
dns: 5353
{{- end -}}

{{/*
Secret TLS d'un service (TO-DO 262), ou vide : le core garde alors son
certificat auto-signé. Argument : (dict "root" $ "service" "ldaps").
*/}}
{{- define "vaultaire.tlsSecret" -}}
{{- $v := index .root.Values.tls .service -}}
{{- if $v.existingSecret -}}
{{- $v.existingSecret -}}
{{- else if and .root.Values.tls.certManager.enabled (has .service .root.Values.tls.certManager.services) -}}
{{- printf "%s-%s-tls" (include "vaultaire.fullname" .root) .service -}}
{{- end -}}
{{- end -}}

{{/* Noms DNS du Service, que tout certificat émis doit couvrir. */}}
{{- define "vaultaire.serviceDnsNames" -}}
{{- $f := include "vaultaire.fullname" . -}}
{{- toJson (list $f (printf "%s.%s.svc" $f .Release.Namespace) (printf "%s.%s.svc.cluster.local" $f .Release.Namespace)) -}}
{{- end -}}

{{/* Contrôles faits avant tout rendu : jamais de mot de passe par défaut. */}}
{{- define "vaultaire.validate" -}}
{{- if not .Values.auth.existingSecret -}}
{{- if not .Values.auth.dbPassword -}}
{{- fail "auth.existingSecret (recommandé) ou auth.dbPassword est requis" -}}
{{- end -}}
{{- if and .Values.config.admin.enabled (not .Values.auth.adminPassword) -}}
{{- fail "auth.existingSecret (recommandé) ou auth.adminPassword est requis" -}}
{{- end -}}
{{- if and .Values.mariadb.enabled (not .Values.auth.dbRootPassword) -}}
{{- fail "auth.existingSecret (recommandé) ou auth.dbRootPassword est requis avec mariadb.enabled" -}}
{{- end -}}
{{- end -}}
{{- with .Values.tls.certManager -}}
{{- if .enabled -}}
{{- if not .issuerRef.name -}}
{{- fail "tls.certManager.enabled : tls.certManager.issuerRef.name est requis" -}}
{{- end -}}
{{- range .services -}}
{{- if not (has . (list "ldaps" "web" "api")) -}}
{{- fail (printf "tls.certManager.services : %q inconnu (ldaps, web, api)" .) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and (gt (int .Values.replicaCount) 1) .Values.mariadb.enabled -}}
{{- /* Possible, mais la base embarquée n'est pas répliquée : dit dans NOTES. */ -}}
{{- end -}}
{{- end -}}
