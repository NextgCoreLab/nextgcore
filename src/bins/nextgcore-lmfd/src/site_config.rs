//! Cell and TRP coordinates from configuration (issue #103).
//!
//! # What was missing
//!
//! `LmfContext::cell_registry` is what every geometric solver reads: with it empty,
//! `try_real_solve` returns `None` and a DetermineLocation ends in
//! `SolverFailed` → 500. And **the only writer was
//! `LmfContext::set_cell_coord`, called exclusively from `#[cfg(test)]` code**.
//! So a deployed LMF had an empty registry and could never produce a fix, no matter
//! how many measurements arrived.
//!
//! The gap was a *configuration surface*, not a solver: the maths, the ENU
//! conversion and the E-CID/Multi-RTT solvers were all already there and tested,
//! reading a registry nothing in production ever filled.
//!
//! # Where the coordinates come from
//!
//! `lmf.positioning.cells` and `lmf.positioning.trps` in the same YAML file the
//! daemon already reads for `lmf.sbi.oauth2.require`. Reading it there rather than
//! adding a flag or a second file, because the file exists, the reader exists, and
//! a deployment that already mounts `lmf.yaml` gains this without a compose change.
//!
//! ```yaml
//! lmf:
//!   positioning:
//!     # Serving-cell coordinates, keyed by the id the measurement reports use.
//!     cells:
//!       - id: pci-42          # or an NR-CGI; whatever the reports key on
//!         lat: 37.5665
//!         lon: 126.9780
//!         height: 38.0        # optional, metres above the WGS-84 ellipsoid
//!     # TRP reference points. Same shape; kept as a separate list because
//!     # TS 38.455 §8.2.6 makes TRP information its own exchange, and an operator
//!     # provisioning one is not necessarily provisioning the other.
//!     trps:
//!       - id: trp-1
//!         lat: 37.5670
//!         lon: 126.9790
//! ```
//!
//! # What is validated, and what a bad entry does
//!
//! An entry with a latitude outside ±90, a longitude outside ±180, or an empty id
//! is **rejected individually and named**, and the rest of the list still loads.
//! Rejecting the whole file would make one typo cost every cell; accepting a
//! nonsense coordinate would put a solver's output somewhere impossible and report
//! it as a fix, which is the failure mode #103 exists to remove.
//!
//! Loading nothing is not an error: an LMF with no coordinates configured is a
//! valid (if non-functional) deployment, and it already fails loudly at
//! positioning time rather than fabricating an answer.

use crate::positioning::TrpCoord;

/// One configured reference point.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteCoord {
    /// The key measurement reports use for this point — an NR-CGI, a `pci-<n>`, or
    /// a TRP id. Not interpreted: whatever a report says is what the registry is
    /// looked up by, so the operator's spelling has to match the RAN's.
    pub id: String,
    /// The coordinate.
    pub coord: TrpCoord,
}

/// Everything `lmf.positioning` yielded, plus what it rejected.
#[derive(Debug, Default, PartialEq)]
pub struct SiteConfig {
    /// Serving-cell coordinates.
    pub cells: Vec<SiteCoord>,
    /// TRP reference points.
    pub trps: Vec<SiteCoord>,
    /// One message per rejected entry, so a mistyped coordinate is visible in the
    /// startup log rather than silently absent from the registry.
    pub rejected: Vec<String>,
}

impl SiteConfig {
    /// How many reference points loaded, across both lists.
    pub fn len(&self) -> usize {
        self.cells.len() + self.trps.len()
    }

    /// Whether nothing loaded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse `lmf.positioning` out of an already-parsed YAML document.
///
/// Split from the file read so it is testable without a filesystem, which is what
/// lets the round trip be asserted against a literal document.
///
/// Root-key agnostic, like `oauth2_required`: any top-level section may carry
/// `positioning`. The shipped files use `lmf`, but an overlay that renames the
/// section should not silently lose its coordinates.
pub fn parse_site_config(doc: &serde_yaml::Value) -> SiteConfig {
    let mut out = SiteConfig::default();
    let Some(map) = doc.as_mapping() else {
        return out;
    };
    for section in map.values() {
        let Some(positioning) = section.get("positioning") else {
            continue;
        };
        collect(
            positioning.get("cells"),
            "cells",
            &mut out.cells,
            &mut out.rejected,
        );
        collect(
            positioning.get("trps"),
            "trps",
            &mut out.trps,
            &mut out.rejected,
        );
    }
    out
}

/// Read one list, appending accepted entries and rejection reasons.
fn collect(
    node: Option<&serde_yaml::Value>,
    what: &str,
    into: &mut Vec<SiteCoord>,
    rejected: &mut Vec<String>,
) {
    let Some(seq) = node.and_then(|n| n.as_sequence()) else {
        return;
    };
    for (idx, entry) in seq.iter().enumerate() {
        match parse_entry(entry) {
            Ok(site) => into.push(site),
            Err(reason) => rejected.push(format!("lmf.positioning.{what}[{idx}]: {reason}")),
        }
    }
}

/// One entry: `{ id, lat, lon, height? }`.
fn parse_entry(entry: &serde_yaml::Value) -> Result<SiteCoord, String> {
    let id = entry
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing or empty 'id'".to_string())?
        .to_string();
    let lat =
        number(entry.get("lat")).ok_or_else(|| format!("{id}: missing or non-numeric 'lat'"))?;
    let lon =
        number(entry.get("lon")).ok_or_else(|| format!("{id}: missing or non-numeric 'lon'"))?;
    // Height is optional: an operator who does not know a mast's altitude should
    // not have to invent one, and the 2-D solvers do not read it.
    let height = number(entry.get("height")).unwrap_or(0.0);

    if !(-90.0..=90.0).contains(&lat) {
        return Err(format!("{id}: latitude {lat} is outside ±90"));
    }
    if !(-180.0..=180.0).contains(&lon) {
        return Err(format!("{id}: longitude {lon} is outside ±180"));
    }
    if !lat.is_finite() || !lon.is_finite() || !height.is_finite() {
        return Err(format!("{id}: a coordinate component is not finite"));
    }
    Ok(SiteCoord {
        id,
        coord: TrpCoord::new(lat, lon, height),
    })
}

/// A YAML scalar as `f64`, accepting an integer as well as a float — `lat: 37`
/// is a legitimate way to write a coordinate and refusing it would be a trap.
fn number(node: Option<&serde_yaml::Value>) -> Option<f64> {
    let node = node?;
    node.as_f64().or_else(|| node.as_i64().map(|i| i as f64))
}

/// Read the configuration file and load every accepted coordinate into the global
/// LMF context's registry.
///
/// Returns the parsed configuration, so the caller can log what happened. An
/// unreadable or unparsable file yields an empty configuration rather than an
/// error: the daemon already tolerates that for `oauth2_required`, and failing
/// startup over a missing optional section would be a behaviour change for every
/// existing deployment.
pub fn load_into_context(config_path: &str) -> SiteConfig {
    let Ok(content) = std::fs::read_to_string(config_path) else {
        log::info!(
            "LMF positioning: no readable config at {config_path}; the cell/TRP registry is \
             EMPTY, so DetermineLocation will report no fix rather than a fabricated one"
        );
        return SiteConfig::default();
    };
    let doc = match serde_yaml::from_str::<serde_yaml::Value>(&content) {
        Ok(v) => v,
        Err(e) => {
            log::warn!(
                "LMF positioning: {config_path} is not valid YAML ({e}); no coordinates loaded"
            );
            return SiteConfig::default();
        }
    };
    let cfg = parse_site_config(&doc);
    for reason in &cfg.rejected {
        log::error!("LMF positioning: rejected {reason}");
    }
    if cfg.is_empty() {
        log::warn!(
            "LMF positioning: no lmf.positioning.cells or .trps configured. Every geometric \
             solver reads this registry, so DetermineLocation will report NO FIX (500 \
             POSITIONING_FAILED) until coordinates are provisioned. See the LMF configuration \
             docs for the YAML shape."
        );
        return cfg;
    }
    apply(&cfg);
    log::info!(
        "LMF positioning: loaded {} cell(s) and {} TRP(s) into the reference-point registry{}",
        cfg.cells.len(),
        cfg.trps.len(),
        if cfg.rejected.is_empty() {
            String::new()
        } else {
            format!(
                " ({} entry/entries rejected, see above)",
                cfg.rejected.len()
            )
        }
    );
    cfg
}

/// Write an already-parsed configuration into the global registry.
///
/// Separate from [`load_into_context`] so a test can exercise the context side
/// without a file, and so the file side can be exercised without the global.
pub fn apply(cfg: &SiteConfig) {
    let ctx = crate::context::lmf_self();
    let Ok(guard) = ctx.read() else {
        log::error!("LMF positioning: context lock poisoned; coordinates NOT loaded");
        return;
    };
    for site in cfg.cells.iter().chain(cfg.trps.iter()) {
        guard.set_cell_coord(site.id.clone(), site.coord);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).expect("test YAML parses")
    }

    #[test]
    fn cells_and_trps_are_parsed_with_an_optional_height() {
        let cfg = parse_site_config(&doc(r#"
lmf:
  positioning:
    cells:
      - id: pci-42
        lat: 37.5665
        lon: 126.9780
        height: 38.0
      - id: pci-43
        lat: 37
        lon: 127
    trps:
      - id: trp-1
        lat: -33.8688
        lon: 151.2093
"#));
        assert!(cfg.rejected.is_empty(), "{:?}", cfg.rejected);
        assert_eq!(cfg.cells.len(), 2);
        assert_eq!(cfg.trps.len(), 1);
        assert_eq!(cfg.cells[0].id, "pci-42");
        assert_eq!(cfg.cells[0].coord, TrpCoord::new(37.5665, 126.9780, 38.0));
        assert_eq!(
            cfg.cells[1].coord,
            TrpCoord::new(37.0, 127.0, 0.0),
            "an INTEGER latitude is a legitimate way to write a coordinate, and height \
             defaults to 0 rather than being required"
        );
        assert_eq!(cfg.trps[0].id, "trp-1");
    }

    /// A bad entry is rejected INDIVIDUALLY and named; the rest still load.
    /// Rejecting the file would make one typo cost every cell.
    #[test]
    fn a_bad_entry_is_named_and_the_rest_still_load() {
        let cfg = parse_site_config(&doc(r#"
lmf:
  positioning:
    cells:
      - id: good
        lat: 10.0
        lon: 20.0
      - id: too-far-north
        lat: 91.0
        lon: 20.0
      - id: too-far-east
        lat: 10.0
        lon: 181.0
      - lat: 10.0
        lon: 20.0
      - id: no-lat
        lon: 20.0
"#));
        assert_eq!(
            cfg.cells.len(),
            1,
            "only the good entry loads, got {:?}",
            cfg.cells
        );
        assert_eq!(cfg.cells[0].id, "good");
        assert_eq!(cfg.rejected.len(), 4, "{:?}", cfg.rejected);
        // Every rejection names the list, the index and the reason, so an operator
        // can find the line rather than being told "some entry was bad".
        assert!(cfg.rejected[0].contains("cells[1]") && cfg.rejected[0].contains("±90"));
        assert!(cfg.rejected[1].contains("cells[2]") && cfg.rejected[1].contains("±180"));
        assert!(cfg.rejected[2].contains("cells[3]") && cfg.rejected[2].contains("'id'"));
        assert!(cfg.rejected[3].contains("cells[4]") && cfg.rejected[3].contains("'lat'"));
    }

    #[test]
    fn an_absent_positioning_section_yields_nothing_and_is_not_an_error() {
        let cfg = parse_site_config(&doc("lmf:\n  sbi:\n    server: []\n"));
        assert!(cfg.is_empty());
        assert!(cfg.rejected.is_empty());
    }

    /// Root-key agnostic, like `oauth2_required`: an overlay that renames the
    /// top-level section must not silently lose its coordinates.
    #[test]
    fn the_section_is_found_under_any_top_level_key() {
        let cfg = parse_site_config(&doc(
            "some_other_root:\n  positioning:\n    cells:\n      - id: c\n        lat: 1\n        lon: 2\n",
        ));
        assert_eq!(cfg.cells.len(), 1);
    }

    /// The exact boundaries load rather than being rejected off-by-one.
    #[test]
    fn the_coordinate_extremes_are_accepted() {
        let cfg = parse_site_config(&doc(r#"
lmf:
  positioning:
    cells:
      - id: north-pole
        lat: 90
        lon: 180
      - id: south-pole
        lat: -90
        lon: -180
"#));
        assert!(cfg.rejected.is_empty(), "{:?}", cfg.rejected);
        assert_eq!(cfg.cells.len(), 2);
    }
}
