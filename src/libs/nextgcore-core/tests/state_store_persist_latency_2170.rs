//! #2170 (R42 on #2165) item 3: what a request-path persist costs, and what
//! concurrent persists of one store cost each other through the path lock
//! (held across encode, write and fsync). A measurement, not a pass/fail
//! gate, so it is `#[ignore]`d: run with
//! `cargo test -p nextgcore-core --test state_store_persist_latency_2170 -- --ignored --nocapture`.

use nextgcore_core::state_store::StateStore;
use std::time::{Duration, Instant};

fn doc(records: usize) -> serde_json::Value {
    // A pcfd-like snapshot: `records` associations of ~400 bytes each.
    serde_json::json!({
        "associations": (0..records).map(|i| serde_json::json!({
            "id": format!("{i:032x}"), "supi": format!("imsi-0010100000{i:05}"),
            "notificationUri": format!("http://amf.example.org/npcf-callback/v1/{i}"),
            "triggers": ["LOC_CH", "PRA_CH", "SERV_AREA_CH", "RFSP_CH"],
            "servAreaRes": {"restrictionType": "ALLOWED_AREAS", "areas": [{"tacs": ["000001", "000002"]}]},
        })).collect::<Vec<_>>()
    })
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

#[test]
#[ignore]
fn measure_persist_latency_2170() {
    let dir = std::env::temp_dir().join(format!("ngc-state-latency-2170-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for records in [100usize, 1000, 5000] {
        let d = doc(records);
        let bytes = serde_json::to_vec_pretty(&d).unwrap().len();
        for writers in [1usize, 8] {
            let path = dir.join(format!("nf-{records}-{writers}.json"));
            let handles: Vec<_> = (0..writers)
                .map(|_| {
                    let (path, d) = (path.clone(), d.clone());
                    std::thread::spawn(move || {
                        let store = StateStore::new(Some(path));
                        (0..40)
                            .map(|_| {
                                let t = Instant::now();
                                store.persist_with(|| d.clone()).unwrap();
                                t.elapsed()
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            let mut all: Vec<Duration> = handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect();
            all.sort();
            println!(
                "records={records:5} bytes={bytes:8} writers={writers}: p50={:?} p99={:?} max={:?}",
                percentile(&all, 0.5),
                percentile(&all, 0.99),
                all.last().unwrap()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
