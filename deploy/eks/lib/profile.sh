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
  # Directory deploy-eks.sh renders; empty means PROFILE_DIR. The demo profile
  # points it at the deploy/eks/overlays/demo-<key>/ overlay a run selects (#1395).
  PROFILE_RENDER_DIR=""
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
  # Prints how to build the profile's missing binaries; build-and-push.sh
  # calls it when some are missing. Reads CORE_DIR, SIM_DIR, CORE_BIN_DIR and
  # the MISSING_CORE_BINS / MISSING_SIM_BINS arrays (bare binary names).
  # shellcheck disable=SC2317
  profile_build_hint() { :; }

  # shellcheck source=/dev/null
  source "${PROFILE_DIR}/profile.env" || {
    printf 'profile %s: profile.env failed\n' "${name}" >&2
    return 1
  }

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

# nextg_rollout_wait KIND/NAME TIMEOUT_SECONDS [warn] (#1651)
#   `kubectl rollout status KIND/NAME -n NAMESPACE --timeout=TIMEOUT_SECONDSs`,
#   which only reports a crash-looping pod once its timeout expires. Every
#   NEXTG_ROLLOUT_POLL seconds (a positive integer, default 5) lib/crashloop.py
#   checks the pods of the workload's current revision. A container that is not
#   Ready after more than NEXTG_ROLLOUT_RESTART_LIMIT restarts (default 3;
#   CrashLoopBackOff included) ends the wait at once with the container's last
#   log lines. The deploy then fails through `die` when the caller defines one,
#   unless the third argument is `warn` (a non-critical workload such as
#   monitoring); otherwise this returns 3. Returns the rollout's own status when
#   it ends first. A check that cannot list the cluster gives no verdict and the
#   wait goes on. An INT or TERM during the wait stops the background rollout
#   wait too, then takes its usual effect: bash starts a background job with INT
#   ignored, so without this it would outlive the deploy (and any lock it holds)
#   until its own timeout.
NEXTG_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
nextg_rollout_wait() {
  local target="$1" timeout="$2" mode="${3:-}" poll="${NEXTG_ROLLOUT_POLL:-5}"
  local dir pid rc=0 ticks=0 found pod container reason restarts prev_int prev_term
  if ! [[ "${poll}" =~ ^[1-9][0-9]*$ ]]; then
    warn "NEXTG_ROLLOUT_POLL must be a positive number of seconds, not '${poll}'; using 5"
    poll=5
  fi
  dir="$(mktemp -d)"
  kubectl rollout status "${target}" -n "${NAMESPACE}" --timeout="${timeout}s" &
  pid=$!
  prev_int="$(trap -p INT)"
  prev_term="$(trap -p TERM)"
  # On a signal: stop the background wait, restore the caller's traps, then
  # deliver the signal again so it acts as it would have.
  trap 'kill "${pid}" 2>/dev/null; wait "${pid}" 2>/dev/null; rm -rf "${dir}"; trap - INT TERM; eval "${prev_int}"; eval "${prev_term}"; kill -s INT "${BASHPID}"' INT
  trap 'kill "${pid}" 2>/dev/null; wait "${pid}" 2>/dev/null; rm -rf "${dir}"; trap - INT TERM; eval "${prev_int}"; eval "${prev_term}"; kill -s TERM "${BASHPID}"' TERM
  while kill -0 "${pid}" 2>/dev/null; do
    sleep 0.2
    ticks=$((ticks + 1))
    (( ticks % (poll * 5) == 0 )) || continue
    kubectl get deployments,statefulsets,replicasets -n "${NAMESPACE}" -o json \
      >"${dir}/workloads.json" 2>/dev/null || continue
    kubectl get pods -n "${NAMESPACE}" -o json >"${dir}/pods.json" 2>/dev/null || continue
    found="$(python3 "${NEXTG_LIB_DIR}/crashloop.py" \
      "${dir}/workloads.json" "${dir}/pods.json" "${target}")" && continue
    [[ -n "${found}" ]] || continue
    kill "${pid}" 2>/dev/null
    wait "${pid}" 2>/dev/null
    rm -rf "${dir}"
    trap - INT TERM; eval "${prev_int}"; eval "${prev_term}"
    while read -r pod container reason restarts; do
      warn "${target}: pod ${pod} container ${container} is crash-looping (${reason}, ${restarts} restarts); its last log lines:"
      kubectl logs "${pod}" -c "${container}" -n "${NAMESPACE}" --previous --tail=20 2>/dev/null \
        || kubectl logs "${pod}" -c "${container}" -n "${NAMESPACE}" --tail=20 2>/dev/null \
        || true
    done <<<"${found}"
    if [[ "${mode}" != warn ]] && declare -F die >/dev/null; then
      die "${target} is crash-looping; not waiting out its ${timeout}s rollout timeout"
    fi
    return 3
  done
  wait "${pid}" || rc=$?
  rm -rf "${dir}"
  trap - INT TERM; eval "${prev_int}"; eval "${prev_term}"
  return "${rc}"
}
