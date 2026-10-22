# shellcheck shell=bash
# shellcheck disable=SC2034  # variables are read by the scripts that source this
# Profile loader shared by build-and-push.sh and deploy-eks.sh.
#
# A profile is a directory deploy/eks/profiles/<name>/ holding:
#   kustomization.yaml  the overlay deploy-eks.sh renders
#   profile.env         sourced bash: namespace, image lists, cargo features,
#                       tag suffix, and the postrender/rollout/summary hooks
# PROFILE=5g is the default and reproduces the pre-profile behaviour exactly.

# nextg_load_profile <name>
#   Sources profiles/<name>/profile.env after resetting every PROFILE_* knob to
#   its neutral default, so a profile only states what it needs. Sets
#   PROFILE_NAME, PROFILE_DIR and PROFILE_DRYRUN_FILE.
nextg_load_profile() {
  local name="$1"
  local eks_dir
  eks_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  case "${name}" in
    ''|*/*|.*) printf 'invalid PROFILE %q\n' "${name}" >&2; return 1 ;;
  esac
  if [[ ! -f "${eks_dir}/profiles/${name}/profile.env" ]]; then
    printf 'unknown PROFILE=%s; available: %s\n' "${name}" \
      "$(cd "${eks_dir}/profiles" && printf '%s ' */ | tr -d /)" >&2
    return 1
  fi

  PROFILE_NAME="${name}"
  PROFILE_DIR="${eks_dir}/profiles/${name}"
  # 5g keeps the historical name, which .gitignore and docs already know.
  if [[ "${name}" == 5g ]]; then
    PROFILE_DRYRUN_FILE="rendered.dryrun.yaml"
  else
    PROFILE_DRYRUN_FILE="rendered.dryrun.${name}.yaml"
  fi

  PROFILE_NAMESPACE=""
  PROFILE_NAMESPACE_MANIFEST=""
  PROFILE_POD_SECURITY=""
  PROFILE_KUSTOMIZE_FLAGS=""
  PROFILE_CARGO_FEATURES=""
  PROFILE_TAG_SUFFIX=""
  PROFILE_CORE_NFS=()
  PROFILE_SIM_IMAGES=()
  PROFILE_ADVERTISE_NFS=""
  PROFILE_HNET_SECRET=false
  PROFILE_DATAPLANE_DEPLOYMENT=""
  PROFILE_DATAPLANE_PATCH=""
  # shellcheck disable=SC2317  # defaults, overridden by profile.env
  profile_rollout() { :; }
  # shellcheck disable=SC2317
  profile_summary() { :; }
  # shellcheck disable=SC2317
  profile_postrender() { :; }

  # shellcheck source=/dev/null
  source "${PROFILE_DIR}/profile.env"

  if [[ -z "${PROFILE_NAMESPACE}" ]]; then
    printf 'profile %s sets no PROFILE_NAMESPACE\n' "${name}" >&2
    return 1
  fi
}

# Space-separated simulator image names of the loaded profile.
nextg_profile_sim_names() {
  local entry out=()
  for entry in "${PROFILE_SIM_IMAGES[@]}"; do
    out+=("${entry%%:*}")
  done
  echo "${out[*]}"
}
