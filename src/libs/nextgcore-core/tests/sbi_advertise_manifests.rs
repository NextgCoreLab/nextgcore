//! #1312, #1322: the NFs that take `NEXTGCORE_SBI_ADVERTISE` get it, set to the pod
//! IP, in the k8s manifests (which the EKS profiles build on) and the Helm chart,
//! so what they register with the NRF is set apart from what they bind.

use std::path::Path;

const NFS: [&str; 8] = ["ausf", "bsf", "nssf", "pcf", "udm", "udr", "amf", "smf"];

fn sets_the_pod_ip(text: &str) -> bool {
    let Some(at) = text.find("- name: NEXTGCORE_SBI_ADVERTISE") else {
        return false;
    };
    let rest = &text[at..];
    let end = rest[1..].find("- name:").map_or(rest.len(), |e| e + 1);
    rest[..end].contains("fieldPath: status.podIP")
}

#[test]
fn the_k8s_and_helm_manifests_advertise_the_pod_ip() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for nf in NFS {
        for rel in [
            format!("k8s/manifests/{nf}.yaml"),
            format!("deploy/helm/nextgcore/templates/{nf}.yaml"),
        ] {
            let text = std::fs::read_to_string(root.join(&rel)).unwrap();
            assert!(
                sets_the_pod_ip(&text),
                "{rel}: no NEXTGCORE_SBI_ADVERTISE from status.podIP"
            );
        }
    }
}

#[test]
fn the_check_needs_the_pod_ip_on_that_variable() {
    let other = "- name: NEXTGCORE_SBI_ADVERTISE\n  value: x\n- name: POD_IP\n  valueFrom:\n    fieldRef:\n      fieldPath: status.podIP\n";
    assert!(!sets_the_pod_ip(other));
    let good = "- name: NEXTGCORE_SBI_ADVERTISE\n  valueFrom:\n    fieldRef:\n      fieldPath: status.podIP\n";
    assert!(sets_the_pod_ip(good));
}
