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

{{/*
Name of the ConfigMap carrying every NF config.
*/}}
{{- define "nextgcore.configMapName" -}}
{{ .Release.Name }}-configs
{{- end }}

{{/*
In-cluster host of the NRF Service. Release-scoped, so two releases in one
namespace do not cross-register.
*/}}
{{- define "nextgcore.nrfHost" -}}
{{ .Release.Name }}-nrf.{{ .Release.Namespace }}.svc.cluster.local
{{- end }}

{{- define "nextgcore.nrfUri" -}}
{{ .Values.global.sbi.scheme }}://{{ include "nextgcore.nrfHost" . }}:{{ .Values.global.sbi.port }}
{{- end }}

{{/*
MongoDB connection URI. Points at the in-chart StatefulSet unless the operator
overrides mongodb.externalUri.
*/}}
{{- define "nextgcore.dbUri" -}}
{{- if .Values.mongodb.externalUri -}}
{{ .Values.mongodb.externalUri }}
{{- else -}}
mongodb://{{ .Release.Name }}-mongodb.{{ .Release.Namespace }}.svc.cluster.local:27017/{{ .Values.mongodb.database }}
{{- end -}}
{{- end }}

{{/*
initContainer that rewrites the NF's advertised SBI address from 0.0.0.0 to the
pod IP.

WHY: configmap.yaml sets sbi.server[0].address to 0.0.0.0, and that one value
feeds BOTH the listen socket and the ipv4Addresses registered with the NRF. The
bind address must stay 0.0.0.0 inside a pod, but an NFProfile advertising
0.0.0.0 hands every consumer an address it cannot dial -- discovery "succeeds"
and the call fails. A ConfigMap mount is read-only and the pod IP is unknown
until scheduling, so the rewritten copy lands in an emptyDir.

Call with a dict: {{ include "nextgcore.advertiseInit" (dict "nf" "ausf") }}
The AMF does NOT use this -- it reads AMF_SBI_ADDR from the environment
(amfd/src/lib.rs:811) and never consults its YAML for the profile.
*/}}
{{- define "nextgcore.advertiseInit" -}}
- name: rewrite-advertise-addr
  image: busybox:1.36
  env:
    - name: POD_IP
      valueFrom:
        fieldRef:
          fieldPath: status.podIP
    - name: NF_NAME
      value: {{ .nf }}
  command:
    - sh
    - -c
    - |
      set -eu
      echo "[advertise] pod IP: $POD_IP"
      case "$POD_IP" in
        *[0-9].[0-9]*) ;;
        *) echo "[advertise] FATAL: POD_IP is not IPv4: '$POD_IP'" >&2; exit 1 ;;
      esac
      cp "/tmp/config-template/${NF_NAME}.yaml" "/etc/nextgcore-resolved/${NF_NAME}.yaml"
      sed -i "s|^\( *- address:\) *0\.0\.0\.0 *$|\1 $POD_IP|" "/etc/nextgcore-resolved/${NF_NAME}.yaml"
      if grep -qE '^ *- address: *0\.0\.0\.0 *$' "/etc/nextgcore-resolved/${NF_NAME}.yaml"; then
        echo "[advertise] FATAL: a 0.0.0.0 advertise address survived" >&2
        exit 1
      fi
      echo "[advertise] ${NF_NAME}.yaml advertise address set to $POD_IP"
  volumeMounts:
    - name: config
      mountPath: /tmp/config-template
      readOnly: true
    - name: config-resolved
      mountPath: /etc/nextgcore-resolved
{{- end }}

{{/*
initContainer that blocks until the NRF SBI port accepts a connection. Every NF
registers with the NRF at startup, and a failed registration is not retried.
*/}}
{{- define "nextgcore.waitForNrf" -}}
- name: wait-nrf
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      until nc -z {{ include "nextgcore.nrfHost" . }} {{ .Values.global.sbi.port }}; do
        echo "waiting for nrf"
        sleep 2
      done
{{- end }}

{{/*
initContainer that blocks until MongoDB accepts a connection.
*/}}
{{- define "nextgcore.waitForMongo" -}}
- name: wait-mongodb
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      until nc -z {{ .Release.Name }}-mongodb.{{ .Release.Namespace }}.svc.cluster.local 27017; do
        echo "waiting for mongodb"
        sleep 2
      done
{{- end }}

{{/*
The two volumes every config-driven NF needs: the ConfigMap template and the
emptyDir the rewritten copy lands in.
*/}}
{{- define "nextgcore.configVolumes" -}}
- name: config
  configMap:
    name: {{ include "nextgcore.configMapName" . }}
- name: config-resolved
  emptyDir: {}
- name: logs
  emptyDir: {}
{{- end }}

{{/*
Config + log mounts for an NF container. The config mount points at the
REWRITTEN copy, never the raw ConfigMap.
*/}}
{{- define "nextgcore.configMounts" -}}
{{/*
`rewritten` selects the source volume and MUST match whether this NF has the
rewrite-advertise-addr initContainer:

  rewritten=true  -> config-resolved (the emptyDir the initContainer fills)
  rewritten=false -> config          (the ConfigMap itself)

Getting this wrong fails silently and confusingly: mounting config-resolved
with a subPath when nothing populated the emptyDir makes kubelet create an
empty DIRECTORY at that path, and the NF logs
"Could not read config file: Is a directory (os error 21). Using defaults."
then runs on defaults and never registers. Observed on the AMF.
*/}}
{{- if .rewritten }}
- name: config-resolved
{{- else }}
- name: config
{{- end }}
  mountPath: /etc/nextgcore/{{ .nf }}.yaml
  subPath: {{ .nf }}.yaml
  readOnly: true
- name: logs
  mountPath: /var/log/nextgcore
{{- end }}

{{/*
tcpSocket probes on the SBI port.

NEVER httpGet: nextgcore-sbi builds its server with hyper's http2::Builder only
(h2c prior knowledge, no HTTP/1.1 fallback, no ALPN), so kubelet's HTTP/1.1
probe can never succeed. /health and /ready exist but are unreachable from
kubelet, and the failing liveness probe SIGKILLs a healthy NF roughly every
90s. The chart used to do exactly this on 9 of its NFs.
*/}}
{{- define "nextgcore.sbiProbes" -}}
readinessProbe:
  tcpSocket:
    port: sbi
  initialDelaySeconds: 5
  periodSeconds: 10
livenessProbe:
  tcpSocket:
    port: sbi
  initialDelaySeconds: 15
  periodSeconds: 30
{{- end }}
