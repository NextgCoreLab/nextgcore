#!/usr/bin/env bash
# compose-tls-init.sh — the certificate source of the compose stacks (#1617).
#
# Run by each stack's one-shot `sbi-tls` service, as root, before any NF:
#
#   1. generate-dev-certs.sh issues the dev PKI into /pki, a volume only this
#      service mounts. The CA key never leaves it. Re-running keeps every
#      certificate that is still current (the generator's own rule), so a
#      `docker compose up` after a `down` (without -v) reuses the same PKI.
#   2. Every directory mounted under /tls is one NF's volume, named after its
#      nf-identities.txt row: /tls/<name> gets ca.crt, <name>.crt (0444) and
#      <name>.key (0400), the key owned by the user that NF's container runs as
#      and by nobody else's. The NF mounts only its own volume, read-only, at
#      /etc/nextgcore/certs. One NF's container cannot read another's key.
#
# The owner of a key is the image's `nextgcore` user unless SBI_TLS_OWNERS
# names another uid for that volume: "name=uid[:gid] name=uid[:gid] ..."
# (a nextgsim sidecar that drops to its own uid, for example).
#
# A directory under /tls with no row in the table fails the run, so a typo in
# a compose file stops the stack instead of starting an NF without its
# certificate.
set -euo pipefail

SRC="${SBI_TLS_SRC:-/opt/sbi-tls}"
PKI="${SBI_TLS_PKI:-/pki}"
OUT="${SBI_TLS_OUT:-/tls}"

bash "$SRC/generate-dev-certs.sh" --out "$PKI" >/dev/null

default_owner="$(id -u nextgcore):$(id -g nextgcore)"
owner_of() {
    local name="$1" entry
    for entry in ${SBI_TLS_OWNERS:-}; do
        if [[ "${entry%%=*}" == "$name" ]]; then
            local o="${entry#*=}"
            [[ "$o" == *:* ]] || o="$o:$o"
            printf '%s' "$o"
            return
        fi
    done
    printf '%s' "$default_owner"
}

# put SRC DEST MODE OWNER
put() {
    if cmp -s "$1" "$2" && [[ "$(stat -c '%a %u:%g' "$2")" == "${3#0} $4" ]]; then
        return
    fi
    install -m "$3" -o "${4%%:*}" -g "${4#*:}" "$1" "$2.new"
    mv -f "$2.new" "$2"
}

n=0
for dir in "$OUT"/*/; do
    [[ -d "$dir" ]] || continue
    name="$(basename "$dir")"
    if [[ ! -f "$PKI/$name.crt" || ! -f "$PKI/$name.key" ]]; then
        echo "sbi-tls: /tls/$name has no row in nf-identities.txt (no $name.crt)" >&2
        exit 1
    fi
    owner="$(owner_of "$name")"
    # Only this NF's files: anything else in its volume (a renamed row) goes.
    find "$dir" -mindepth 1 -maxdepth 1 \
        ! -name ca.crt ! -name "$name.crt" ! -name "$name.key" -exec rm -rf {} +
    # compose re-runs this service on every `up`, possibly while the NFs run:
    # an unchanged file is left alone, a changed one replaced in one rename.
    put "$PKI/ca.crt" "$dir/ca.crt" 0444 0:0
    put "$PKI/$name.crt" "$dir/$name.crt" 0444 0:0
    put "$PKI/$name.key" "$dir/$name.key" 0400 "$owner"
    chown root:root "$dir"
    chmod 0755 "$dir"
    echo "sbi-tls: $name: $name.crt, $name.key (owner $owner, 0400), ca.crt"
    n=$((n + 1))
done
[[ "$n" -gt 0 ]] || { echo "sbi-tls: no NF volume mounted under $OUT" >&2; exit 1; }
echo "sbi-tls: $n NF certificate volumes ready"
