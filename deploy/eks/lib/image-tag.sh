# shellcheck shell=bash
#
# Shared image-tag derivation for build-and-push.sh and deploy-eks.sh.
#
# WHY THIS IS SHARED RATHER THAN COPIED
#
# The two scripts must agree on the tag with no handoff file between them:
# build-and-push.sh pushes `<nf>:<tag>` and deploy-eks.sh rewrites the manifests
# to the same `<nf>:<tag>`. Two independent copies of this logic would work until
# one drifted, and the failure mode of drift is an ErrImagePull *at best* -- or,
# if the drifted tag happens to exist, a deploy of the wrong build. So it is
# computed in one place and sourced by both.
#
# Both scripts read the same two git repositories, so they derive the same tag
# without either passing anything to the other. If the tree is committed between
# a build and a deploy the tags no longer match, and deploy-eks.sh fails fast on
# a missing ECR tag -- which is correct, because the images no longer correspond
# to the source being deployed.
#
# WHY NOT :latest
#
# A mutable tag makes `kubectl apply` a silent no-op. The Deployment spec text is
# identical before and after a rebuild, so the API server sees no change, writes
# no new ReplicaSet, and the running pods keep the OLD image. `deploy-eks.sh`
# then exits 0, prints "Deployed.", and its `kubectl rollout status` loop passes
# trivially against those stale pods -- so an E2E run reports on code that was
# never deployed. Observed on devtest1: the running AMF was sha256:1338b825
# while the freshly pushed tag was sha256:2665d4ca.
#
# `imagePullPolicy: Always` does NOT save this. It governs what kubelet fetches
# when it starts a container; with no spec change no container is ever restarted,
# so nothing is re-pulled.
#
# TWO REPOSITORIES, TWO TAGS
#
# The 10 core NF images are built from nextgcore and the gnb/ue images from the
# sibling nextgsim, which is a separate repository at its own commit. One tag
# across both would label an image with a SHA that does not describe it, so each
# group is tagged from its own repository's HEAD.

# Derive an immutable image tag from a git repository's HEAD.
#
# Emits `<short-sha>` for a clean tree, `<short-sha>-dirty` when tracked files
# are modified. The `-dirty` suffix is deliberately not an error: local
# iteration on a cluster is a normal workflow, and the suffix is what stops two
# different working trees from colliding on one tag. It is a *warning* in the
# callers, because a dirty tag is not reproducible from the SHA alone.
#
# Note both repos gitignore their staged binary output directories
# (nextgcore/binaries/, nextgsim/docker/binaries/), so populating those for a
# build does not by itself make a tree dirty.
#
# $1: repository path. Prints the tag; returns non-zero if $1 is not a git repo.
nextg_image_tag() {
  local repo="$1" sha dirty=''

  git -C "${repo}" rev-parse --git-dir >/dev/null 2>&1 || {
    printf 'not a git repository: %s\n' "${repo}" >&2
    return 1
  }

  sha="$(git -C "${repo}" rev-parse --short=12 HEAD 2>/dev/null)" || {
    printf 'no HEAD commit in %s (unborn branch?)\n' "${repo}" >&2
    return 1
  }

  # --porcelain covers tracked modifications and staged changes. Untracked files
  # are intentionally ignored: a stray file in the tree does not change what gets
  # built, and counting it would mark nearly every real workspace dirty.
  [[ -n "$(git -C "${repo}" status --porcelain --untracked-files=no 2>/dev/null)" ]] \
    && dirty='-dirty'

  printf '%s%s\n' "${sha}" "${dirty}"
}
