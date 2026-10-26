#!/usr/bin/env bash
# Fail when an image the repo defines is not in the release publish list (#420).
#
# docker/release-images.json is the ONE list release.yml builds and pushes to
# Docker Hub. A list kept by hand drifts: a new NF daemon gets a crate under
# src/bins/ and a compose service, and the release silently ships without it.
# This check makes that drift a red CI run instead. Everything below must be
# either an entry in `images` or a path in `excluded` (with its reason):
#   - every daemon crate under src/bins/;
#   - every tracked Dockerfile (Dockerfile, Dockerfile.*; not *.dockerignore);
#   - every nextgcore-rust/<nf> image a compose file, the Helm chart, the EKS
#     overlay or k8s/ references (it is published as nextgcore-<nf>).
# Run from the repo root: docker/check-release-images.sh
set -euo pipefail

manifest="${1:-docker/release-images.json}"
fail=0
err() { echo "::error::$*"; fail=1; }

command -v jq >/dev/null || { echo "::error::jq is required"; exit 1; }
jq -e '.images | type == "array" and length > 0' "$manifest" >/dev/null \
  || { echo "::error::${manifest}: no .images array"; exit 1; }

images=$(jq -r '.images[].image' "$manifest")
nf_names=$(jq -r '.images[] | select(.nf_name) | .nf_name' "$manifest")
dockerfiles=$(jq -r '.images[].dockerfile' "$manifest" | sort -u)
excluded=$(jq -r '(.excluded // [])[].path' "$manifest")

in_list() { grep -qxF -- "$1" <<<"$2"; }

# The manifest itself.
dups=$(sort <<<"$images" | uniq -d)
[ -z "$dups" ] || err "${manifest}: duplicate images: ${dups//$'\n'/ }"
[ "$(jq '[.images[] | select(.base == true)] | length' "$manifest")" = 1 ] \
  || err "${manifest}: exactly one image must be the base (\"base\": true)"
while IFS=$'\t' read -r image dockerfile context nf; do
  [[ "$image" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || err "${image}: not a valid Docker Hub repository name"
  [ -f "$dockerfile" ] || err "${image}: dockerfile ${dockerfile} does not exist"
  [ -d "$context" ] || err "${image}: context ${context} does not exist"
  if [ -n "$nf" ] && [ ! -d "src/bins/${nf}" ]; then
    err "${image}: nf_name ${nf} has no crate under src/bins/"
  fi
done < <(jq -r '.images[] | [.image, .dockerfile, .context, (.nf_name // "")] | @tsv' "$manifest")
while IFS= read -r p; do
  [ -z "$p" ] || [ -e "$p" ] || err "${manifest}: excluded path ${p} does not exist"
done <<<"$excluded"

# Every daemon crate.
for dir in src/bins/*/; do
  dir=${dir%/}
  name=${dir#src/bins/}
  in_list "$name" "$nf_names" || in_list "$dir" "$excluded" \
    || err "${dir} is not in ${manifest}: add it to .images (or to .excluded with a reason)"
done

# Every tracked Dockerfile.
while IFS= read -r f; do
  case "$f" in *.dockerignore) continue ;; esac
  in_list "$f" "$dockerfiles" || in_list "$f" "$excluded" \
    || err "${f} is not in ${manifest}: add its image to .images (or the file to .excluded with a reason)"
done < <(git ls-files | grep -E '(^|/)Dockerfile(\.[^/]*)?$' || true)

# Every nextgcore-rust/<nf> image the deployments reference.
while IFS= read -r ref; do
  [ -n "$ref" ] || continue
  image="nextgcore-${ref#nextgcore-rust/}"
  in_list "$image" "$images" \
    || err "${ref} is referenced by a compose file, the Helm chart, deploy/eks or k8s/, but ${image} is not in ${manifest}"
done < <(git ls-files docker deploy k8s | grep -E '\.(ya?ml|env|sh)$' | xargs grep -ohE 'nextgcore-rust/[a-z0-9-]+' | sort -u || true)

if [ "$fail" -ne 0 ]; then
  echo "The release publish list is incomplete; see the errors above."
  exit 1
fi
echo "All $(wc -l <<<"$images") images in ${manifest} cover every daemon, Dockerfile and referenced image."
