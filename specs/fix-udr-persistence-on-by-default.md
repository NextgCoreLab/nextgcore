# nextgcore #66 criterion 3: UDR durable state on by default in the shipped Docker config

Verified against `main` @ `77aa0f8`.

Closes #66 criterion 3. The remaining criteria are filed as #191, #192 and #193,
so **this closes #66**.

## The defect

The UDR's durable store existed — `--state-file` / `NEXTGCORE_UDR_STATE_FILE`,
wired since before this issue — and **nothing anywhere switched it on**.
`grep -rn NEXTGCORE_UDR_STATE_FILE docker/ k8s/ deploy/` returned nothing.

#66 calls the UDR its most severe member, and the reason is the shape of the
failure rather than its size: a restart erases every subscriber's
`amf-3gpp-access` and `smf-registration` at once, after which the UDR answers
"not registered" — authoritatively, with a 404 — for subscribers that *are*
registered. A consumer cannot distinguish that from a genuine deprovisioning.

## Why this was not bundled into #190

#190 built the shared store and fixed the corrupt-snapshot data-loss defect. This
is a deployment change, and it turned out to need an image change too, which is
exactly why it was worth separating:

**The container runs as `nextgcore`, not root** (`Dockerfile.nf` ends `USER
nextgcore`), and the core image creates only `/etc/nextgcore`,
`/var/log/nextgcore` and `/var/run/nextgcore`. A Docker named volume mounted onto
a path the image does **not** create is initialised root-owned, so the first
snapshot write would have failed `EACCES` — persistence configured, and silently
not working.

So `Dockerfile.core` now creates `/var/lib/nextgcore` owned by `nextgcore`, and the
volume inherits that ownership. This also prepares the ground for #191 and #192,
whose NFs will want the same directory.

## The change

* `Dockerfile.core` — `/var/lib/nextgcore`, owned by `nextgcore`.
* `docker-compose.yml` — `NEXTGCORE_UDR_STATE_FILE=/var/lib/nextgcore/udr-state.json`
  on the `udr` service, backed by a new `udr_state` **named** volume. Named rather
  than a bind mount because a bind mount arrives owned by the host user, which
  reintroduces the ownership problem the image change just solved.
* Docs in `configuration/udr.md`, including what is *not* covered.

Enabling this is only safe because of #190: a corrupt snapshot is now refused
rather than overwritten, so switching persistence on cannot silently destroy what
it fails to read. Turning it on before that landed would have been the wrong order.

## Verification, and its limit

The criterion's own test is *"restart `udrd` in the E2E stack and assert
previously provisioned `smf-registrations` and `amf-3gpp-access` registrations
survive"*. **CI skips the Docker E2E jobs**, so that test would never run
anywhere — writing it would produce coverage that only appears to exist.

Instead:

* `shipped_docker_config_enables_udr_persistence` reads `docker-compose.yml` from
  `cargo test` and asserts the state file is set, non-empty, backed by a volume
  mounted at its directory, and that the volume is the named one. **Revert-verified:**
  removing the env line fails it.
* `test_persistence_survives_restart` (pre-existing) already proves the
  restore-across-restart mechanism at the store level.

**Not verified:** no container was built or started. The image change in particular
is unexecuted here — `Dockerfile.core` is only exercised by the Docker Build job,
which is skipped. The ownership reasoning above is derived from the Dockerfiles,
not observed. First real `docker compose up` should confirm the UDR logs a snapshot
write rather than `EACCES`.

## Deliberately not covered: Kubernetes and Helm

The `udr` manifest is a `Deployment` with `replicas: 1` and no volume for this.
Persistence there needs a `PersistentVolumeClaim` plus `strategy: Recreate` — a
plain rolling update would have two pods contending for one `ReadWriteOnce`
volume — or conversion to a `StatefulSet`, which is what MongoDB does here
(`volumeClaimTemplates`). That is a storage-topology decision, not a config line,
and criterion 3 asks specifically for the **Docker/E2E** configuration. Stated in
the docs rather than left for someone to discover.

## Definition of done

- [x] UDR persistence enabled in the shipped Docker configuration, on a volume
      that survives container recreation.
- [x] The image provides a state directory the non-root NF user can write.
- [x] Guarded by a test that runs where CI actually runs.
- [x] Documented, including the k8s/Helm gap and the unexecuted image change.
- [ ] k8s/Helm persistence — out of scope, documented.
