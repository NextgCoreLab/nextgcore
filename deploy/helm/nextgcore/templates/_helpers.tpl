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

{{/*
The NRF serves TLS (#1617): every NF dials it over https, presenting its own
certificate. There is no plaintext NRF to opt back into: the NRF refuses NF
management from a client without a verified certificate identity. An explicit
global.sbi.scheme other than https fails the render rather than being ignored.
*/}}
{{- define "nextgcore.nrfUri" -}}
{{- if and .Values.global.sbi.scheme (ne .Values.global.sbi.scheme "https") -}}
{{- fail (printf "global.sbi.scheme=%s: the NRF serves TLS only (#1617), so every NF dials https://; unset it" .Values.global.sbi.scheme) -}}
{{- end -}}
https://{{ include "nextgcore.nrfHost" . }}:{{ .Values.global.sbi.port }}
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
The AMF does not use this: AMF_SBI_ADDR (the pod IP) overrides its
amf.sbi.server[0].address (#1311), so the env var is set instead.
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
registers with the NRF at startup. A failed registration is retried with backoff
(#1482), so this wait only keeps the first attempt from being one that fails.
*/}}
{{- define "nextgcore.waitForNrf" -}}
- name: wait-nrf
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      until nc -z -w 2 {{ include "nextgcore.nrfHost" . }} {{ .Values.global.sbi.port }}; do
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
      until nc -z -w 2 {{ .Release.Name }}-mongodb.{{ .Release.Namespace }}.svc.cluster.local 27017; do
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

{{/*
The nfType each NF registers (TS 29.510 §6.1.6.3.3), the one its certificate
names in RFC 9310 NFTypes, and so the <TYPE> of its NEXTGCORE_<TYPE>_INSTANCE_ID.
*/}}
{{- define "nextgcore.nfType" -}}
{{- $t := dict "nrf" "NRF" "amf" "AMF" "smf" "SMF" "ausf" "AUSF" "udm" "UDM" "udr" "UDR" "pcf" "PCF" "nssf" "NSSF" "bsf" "BSF" -}}
{{- required (printf "no nfType for %s" .) (get $t .) -}}
{{- end -}}

{{/*
The NFs of this chart that dial the NRF (all but the UPF), and the NRF. Each
pins an nfInstanceId and mounts Secret nf-tls-<nf> (#1617).
*/}}
{{- define "nextgcore.nrfNfs" -}}
nrf amf smf ausf udm udr pcf nssf bsf
{{- end -}}

{{/*
An NF's nfInstanceId: .Values.<nf>.nfInstanceId, or a UUID (version 4 layout)
derived from global.siteId, the release namespace, its name and the NF (#753,
#1617). Stable across pod restarts and upgrades, unlike uuidv4, and the same
under `helm template`, `helm install` and GitOps renderers, so the certificate
issued for it (deploy/helm/nf-tls-secrets.sh reads the rendered
<release>-nf-identities ConfigMap) names the ID the NF registers.

The chart used to fall back to the kube-system namespace UID through `lookup`
when global.siteId was empty. `lookup` is empty under `helm template`, so the
identities a certificate is issued from would differ from what `helm install`
pins, and every NF would be refused at the NRF. An empty siteId now fails the
render for any NF whose id is not pinned.

Call with a dict: {{ include "nextgcore.nfInstanceId" (dict "root" . "nf" "ausf") }}
*/}}
{{- define "nextgcore.nfInstanceId" -}}
{{- $v := index .root.Values .nf -}}
{{- if $v.nfInstanceId -}}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" $v.nfInstanceId) -}}
{{- fail (printf "%s.nfInstanceId=%s is not a lower-case UUID version 4 (TS 29.571 §5.3.2)" .nf $v.nfInstanceId) -}}
{{- end -}}
{{- $v.nfInstanceId -}}
{{- else -}}
{{- if not .root.Values.global.siteId -}}
{{- fail (printf "global.siteId is empty and %s.nfInstanceId is unset: set global.siteId (unique per cluster, stable for its life). It salts every derived nfInstanceId, and each NF's certificate must name that ID (#753, #1617)" .nf) -}}
{{- end -}}
{{- $h := sha256sum (printf "%s/%s/%s/%s" .root.Values.global.siteId .root.Release.Namespace .root.Release.Name .nf) -}}
{{- printf "%s-%s-4%s-8%s-%s" (substr 0 8 $h) (substr 8 12 $h) (substr 13 16 $h) (substr 17 20 $h) (substr 20 32 $h) -}}
{{- end -}}
{{- end -}}

{{/*
The name of NF <nf>'s Secret: nf-tls-<nf>, or nf-tls-<nf>-<version> once
global.nrfTls.secretVersion names the version deploy/helm/nf-tls-secrets.sh
(or k8s/nf-tls-secrets.sh) printed.
*/}}
{{- define "nextgcore.nrfTlsSecret" -}}
{{- $ver := .root.Values.global.nrfTls.secretVersion -}}
{{- if $ver -}}
{{- if not (regexMatch "^[0-9a-f]{16}$" $ver) -}}
{{- fail (printf "global.nrfTls.secretVersion=%s is not the 16 hex digits nf-tls-secrets.sh prints" $ver) -}}
{{- end -}}
nf-tls-{{ .nf }}-{{ $ver }}
{{- else -}}
nf-tls-{{ .nf }}
{{- end -}}
{{- end -}}

{{/*
Pod securityContext for an NF that mounts its nf-tls Secret: the files are
mode 0440 to group fsGroup, and every container of the pod runs with fsGroup
as a supplementary group, so the image's non-root nextgcore user reads its key.
*/}}
{{- define "nextgcore.nrfTlsPodSecurity" -}}
securityContext:
  fsGroup: 999
{{- end -}}

{{/*
The nf-tls volume: NF <nf>'s certificate, its key and the CA certificate (never
the CA key), mode 0440. Not optional: a pod whose Secret does not exist does not
start, rather than starting without an identity the NRF would refuse.
*/}}
{{- define "nextgcore.nrfTlsVolume" -}}
- name: nf-tls
  secret:
    secretName: {{ include "nextgcore.nrfTlsSecret" . }}
    defaultMode: 0440
{{- end -}}

{{- define "nextgcore.nrfTlsMount" -}}
- name: nf-tls
  mountPath: /etc/nextgcore/certs
  readOnly: true
{{- end -}}

{{/*
The pinned nfInstanceId, and for an NRF client the NRF TLS client settings: its
own pair, the CA, and the name the NRF's certificate is verified against
(global.nrfTls.serverName; the dev nrf.crt names DNS:nrf, not the Service FQDN).
*/}}
{{- define "nextgcore.nrfTlsEnv" -}}
{{- $type := include "nextgcore.nfType" .nf -}}
# The urn:uuid its certificate names (#753, #1617); listed in ConfigMap
# <release>-nf-identities.
- name: NEXTGCORE_{{ $type }}_INSTANCE_ID
  value: {{ include "nextgcore.nfInstanceId" . | quote }}
{{- if ne .nf "nrf" }}
# NF -> NRF over TLS with this pod's own certificate (#1617).
- name: NEXTGCORE_NRF_TLS_CA
  value: /etc/nextgcore/certs/ca.crt
- name: NEXTGCORE_NRF_TLS_CLIENT_CERT
  value: /etc/nextgcore/certs/{{ .nf }}.crt
- name: NEXTGCORE_NRF_TLS_CLIENT_KEY
  value: /etc/nextgcore/certs/{{ .nf }}.key
{{- with .root.Values.global.nrfTls.serverName }}
- name: NEXTGCORE_NRF_TLS_SERVER_NAME
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
One pod per pinned nfInstanceId: two pods under one ID are one NF instance at
the NRF, and a rolling update's old pod would NFDeregister the ID its
replacement just registered (#753, #1617).
*/}}
{{- define "nextgcore.singleInstance" -}}
{{- if gt (int (index .root.Values .nf).replicas) 1 -}}
{{- fail (printf "%s.replicas > 1 is not supported: every pod would share one nfInstanceId and one certificate (#753, #1617). Run one per release." .nf) -}}
{{- end -}}
{{- end -}}
