//! LOCAL Nlmf_Location model types (TS 29.572) + TS 23.032 GAD encoding.
//!
//! lmfd-LIB-03 (LOCAL): these serde models and the TS 23.032 `to_gad()` /
//! coordinate-uncertainty encoders are transcribed from
//! `specs/TS29572_Nlmf_Location.yaml` (InputData §6.1.6.2.2, LocationData
//! §6.1.6.2.3, GeographicArea / GAD shapes §6.1.6.2.5-.12) and TS 23.032.
//!
//! NOTE (lmfd-LIB-03 follow-up): this module is intentionally LOCAL to the
//! `nextgcore-lmfd` crate. Once a second consumer needs these types (e.g. the
//! AMF for `Namf_Location`, per lmfd-AMF-01), this whole module SHOULD MOVE to
//! `nextgcore-sbi/src/models/nlmf.rs` and be shared. It is kept here for now so the
//! Wave-3 SBI-surface fixes do not touch shared libs.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TS 29.571 ProblemDetails cause values used by lmfd (lmfd-10).
// ---------------------------------------------------------------------------
/// Spec ProblemDetails `cause` enumerations (TS 29.571 §5.2.7.2 / per-operation
/// tables in TS 29.572). Used to fill `application/problem+json` bodies.
pub mod cause {
    pub const INVALID_MSG_FORMAT: &str = "INVALID_MSG_FORMAT";
    pub const MANDATORY_IE_INCORRECT: &str = "MANDATORY_IE_INCORRECT";
    pub const MANDATORY_IE_MISSING: &str = "MANDATORY_IE_MISSING";
    pub const UNSPECIFIED: &str = "UNSPECIFIED";
    pub const UNREACHABLE_USER: &str = "UNREACHABLE_USER";
    pub const POSITIONING_DENIED: &str = "POSITIONING_DENIED";
    pub const POSITIONING_METHOD_FAILURE: &str = "POSITIONING_METHOD_FAILURE";
}

// ---------------------------------------------------------------------------
// SupportedGADShapes enum string values (TS 29.572 §6.1.6.3.x).
// ---------------------------------------------------------------------------
/// `SupportedGADShapes` string values (TS 29.572). Kept as `&str` constants so
/// the (extensible) shape list on `InputData` can be matched without forcing a
/// closed enum on the wire.
pub mod gad_shape {
    pub const POINT: &str = "POINT";
    pub const POINT_UNCERTAINTY_CIRCLE: &str = "POINT_UNCERTAINTY_CIRCLE";
    pub const POINT_UNCERTAINTY_ELLIPSE: &str = "POINT_UNCERTAINTY_ELLIPSE";
    pub const POLYGON: &str = "POLYGON";
    pub const POINT_ALTITUDE: &str = "POINT_ALTITUDE";
    pub const POINT_ALTITUDE_UNCERTAINTY: &str = "POINT_ALTITUDE_UNCERTAINTY";
    pub const ELLIPSOID_ARC: &str = "ELLIPSOID_ARC";
}

/// `AccuracyFulfilmentIndicator` string values (TS 29.572 §6.1.6.3.x).
pub mod accuracy_fulfilment {
    pub const FULFILLED: &str = "REQUESTED_ACCURACY_FULFILLED";
    pub const NOT_FULFILLED: &str = "REQUESTED_ACCURACY_NOT_FULFILLED";
}

/// `PositioningMethod` string values (TS 29.572 §6.1.6.3.x). Note the spec
/// keeps several non-conforming spellings (e.g. `MULTI-RTT`, `SL_AoA`) for
/// backwards compatibility.
pub mod positioning_method {
    pub const CELLID: &str = "CELLID";
    pub const ECID: &str = "ECID";
    pub const OTDOA: &str = "OTDOA";
    pub const BAROMETRIC_PRESSURE: &str = "BAROMETRIC_PRESSURE";
    pub const WLAN: &str = "WLAN";
    pub const BLUETOOTH: &str = "BLUETOOTH";
    pub const MBS: &str = "MBS";
    pub const MOTION_SENSOR: &str = "MOTION_SENSOR";
    pub const DL_TDOA: &str = "DL_TDOA";
    pub const DL_AOD: &str = "DL_AOD";
    pub const MULTI_RTT: &str = "MULTI-RTT";
    pub const NR_ECID: &str = "NR_ECID";
    pub const UL_TDOA: &str = "UL_TDOA";
    pub const UL_AOA: &str = "UL_AOA";
}

// ---------------------------------------------------------------------------
// InputData (TS 29.572 §6.1.6.2.2) — only the IEs lmfd consumes are typed;
// unknown IEs are tolerated (serde ignores them). The `not: [ecgi, ncgi]`
// mutual exclusion is enforced by the handler, not by serde.
// ---------------------------------------------------------------------------

/// `InputData` — Determine Location request body (TS 29.572 §6.1.6.2.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InputData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_client_type: Option<String>,
    #[serde(rename = "correlationID", skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amf_id: Option<String>,
    #[serde(rename = "locationQoS", skip_serializing_if = "Option::is_none")]
    pub location_qos: Option<LocationQoS>,
    #[serde(rename = "supportedGADShapes", skip_serializing_if = "Option::is_none")]
    pub supported_gad_shapes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpsi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldr_type: Option<String>,
    #[serde(rename = "hgmlcCallBackURI", skip_serializing_if = "Option::is_none")]
    pub hgmlc_call_back_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecgi: Option<Ecgi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ncgi: Option<Ncgi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_resp_time: Option<u32>,
    #[serde(rename = "supportedFeatures", skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

/// `LocationQoS` (TS 29.572 §6.1.6.2.7).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LocationQoS {
    #[serde(rename = "hAccuracy", skip_serializing_if = "Option::is_none")]
    pub h_accuracy: Option<f64>,
    #[serde(rename = "vAccuracy", skip_serializing_if = "Option::is_none")]
    pub v_accuracy: Option<f64>,
    #[serde(rename = "verticalRequested", skip_serializing_if = "Option::is_none")]
    pub vertical_requested: Option<bool>,
    #[serde(rename = "responseTime", skip_serializing_if = "Option::is_none")]
    pub response_time: Option<String>,
}

/// `PlmnId` (TS 29.571).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// `Ecgi` — E-UTRAN Cell Global Identity (TS 29.571).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Ecgi {
    #[serde(rename = "plmnId")]
    pub plmn_id: PlmnId,
    #[serde(rename = "eutraCellId")]
    pub eutra_cell_id: String,
}

/// `Ncgi` — NR Cell Global Identity (TS 29.571).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Ncgi {
    #[serde(rename = "plmnId")]
    pub plmn_id: PlmnId,
    #[serde(rename = "nrCellId")]
    pub nr_cell_id: String,
}

// ---------------------------------------------------------------------------
// GeographicArea (TS 29.572 §6.1.6.2.x) — an internally-tagged enum on the
// `shape` discriminator (GADShape, TS 29.572 §6.1.6.2.6) over the TS 23.032
// shapes. Coordinates are the SBI JSON representation (decimal degrees);
// `encode_gad_*` below give the underlying TS 23.032 octet encoding.
// ---------------------------------------------------------------------------

/// `GeographicalCoordinates` (TS 29.572) — decimal-degree lat/lon.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct GeographicalCoordinates {
    pub lon: f64,
    pub lat: f64,
}

/// `UncertaintyEllipse` (TS 29.572).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct UncertaintyEllipse {
    #[serde(rename = "semiMajor")]
    pub semi_major: f64,
    #[serde(rename = "semiMinor")]
    pub semi_minor: f64,
    #[serde(rename = "orientationMajor")]
    pub orientation_major: u16,
}

/// `GeographicArea` — TS 23.032 GAD shape, tagged on `shape` (TS 29.572).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "shape")]
pub enum GeographicArea {
    #[serde(rename = "POINT")]
    Point { point: GeographicalCoordinates },
    #[serde(rename = "POINT_UNCERTAINTY_CIRCLE")]
    PointUncertaintyCircle {
        point: GeographicalCoordinates,
        uncertainty: f64,
    },
    #[serde(rename = "POINT_UNCERTAINTY_ELLIPSE")]
    PointUncertaintyEllipse {
        point: GeographicalCoordinates,
        #[serde(rename = "uncertaintyEllipse")]
        uncertainty_ellipse: UncertaintyEllipse,
        confidence: u8,
    },
    #[serde(rename = "POLYGON")]
    Polygon {
        #[serde(rename = "pointList")]
        point_list: Vec<GeographicalCoordinates>,
    },
    #[serde(rename = "POINT_ALTITUDE")]
    PointAltitude {
        point: GeographicalCoordinates,
        altitude: f64,
    },
    #[serde(rename = "POINT_ALTITUDE_UNCERTAINTY")]
    PointAltitudeUncertainty {
        point: GeographicalCoordinates,
        altitude: f64,
        #[serde(rename = "uncertaintyEllipse")]
        uncertainty_ellipse: UncertaintyEllipse,
        #[serde(rename = "uncertaintyAltitude")]
        uncertainty_altitude: f64,
        confidence: u8,
        #[serde(rename = "vConfidence", skip_serializing_if = "Option::is_none")]
        v_confidence: Option<u8>,
    },
    #[serde(rename = "ELLIPSOID_ARC")]
    EllipsoidArc {
        point: GeographicalCoordinates,
        #[serde(rename = "innerRadius")]
        inner_radius: u32,
        #[serde(rename = "uncertaintyRadius")]
        uncertainty_radius: f64,
        #[serde(rename = "offsetAngle")]
        offset_angle: u16,
        #[serde(rename = "includedAngle")]
        included_angle: u16,
        confidence: u8,
    },
}

impl GeographicArea {
    /// The `shape` discriminator value carried on the wire.
    pub fn shape(&self) -> &'static str {
        match self {
            GeographicArea::Point { .. } => gad_shape::POINT,
            GeographicArea::PointUncertaintyCircle { .. } => gad_shape::POINT_UNCERTAINTY_CIRCLE,
            GeographicArea::PointUncertaintyEllipse { .. } => gad_shape::POINT_UNCERTAINTY_ELLIPSE,
            GeographicArea::Polygon { .. } => gad_shape::POLYGON,
            GeographicArea::PointAltitude { .. } => gad_shape::POINT_ALTITUDE,
            GeographicArea::PointAltitudeUncertainty { .. } => {
                gad_shape::POINT_ALTITUDE_UNCERTAINTY
            }
            GeographicArea::EllipsoidArc { .. } => gad_shape::ELLIPSOID_ARC,
        }
    }
}

/// `PositioningMethodAndUsage` (TS 29.572 §6.1.6.2.x).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PositioningMethodAndUsage {
    pub method: String,
    pub mode: String,
    pub usage: String,
}

/// `LocationData` — Determine Location response body (TS 29.572 §6.1.6.2.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocationData {
    #[serde(rename = "locationEstimate")]
    pub location_estimate: GeographicArea,
    #[serde(
        rename = "accuracyFulfilmentIndicator",
        skip_serializing_if = "Option::is_none"
    )]
    pub accuracy_fulfilment_indicator: Option<String>,
    #[serde(
        rename = "ageOfLocationEstimate",
        skip_serializing_if = "Option::is_none"
    )]
    pub age_of_location_estimate: Option<u16>,
    #[serde(
        rename = "positioningDataList",
        skip_serializing_if = "Option::is_none"
    )]
    pub positioning_data_list: Option<Vec<PositioningMethodAndUsage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub altitude: Option<f64>,
    #[serde(rename = "barometricPressure", skip_serializing_if = "Option::is_none")]
    pub barometric_pressure: Option<u32>,
    #[serde(rename = "velocityEstimate", skip_serializing_if = "Option::is_none")]
    pub velocity_estimate: Option<serde_json::Value>,
    #[serde(rename = "civicAddress", skip_serializing_if = "Option::is_none")]
    pub civic_address: Option<serde_json::Value>,
}

/// `LocationDataExt` = `LocationData` + `AddLocationDatas` (TS 29.572
/// §6.1.6.2.x). `AddLocationDatas` (related/SL-UE location) is out of scope for
/// the Wave-3 SBI-surface fix and modelled as an opaque optional extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocationDataExt {
    #[serde(flatten)]
    pub location_data: LocationData,
    #[serde(rename = "addLocationData", skip_serializing_if = "Option::is_none")]
    pub add_location_data: Option<Vec<serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// TS 23.032 GAD encoding helpers.
// ---------------------------------------------------------------------------

/// Build a `GeographicArea` from a position estimate (lmfd-04).
///
/// Produces the requested GAD `shape`; unknown/unsupported shape strings fall
/// back to `POINT_UNCERTAINTY_CIRCLE` (the universally-supported default per
/// TS 29.572). `uncertainty_m` is the horizontal uncertainty in metres;
/// `confidence` is the 0..100 % confidence.
pub fn to_gad(
    lat: f64,
    lon: f64,
    uncertainty_m: f64,
    confidence: u8,
    shape: &str,
) -> GeographicArea {
    let point = GeographicalCoordinates { lon, lat };
    match shape {
        gad_shape::POINT => GeographicArea::Point { point },
        gad_shape::POINT_UNCERTAINTY_ELLIPSE => GeographicArea::PointUncertaintyEllipse {
            point,
            uncertainty_ellipse: UncertaintyEllipse {
                semi_major: uncertainty_m,
                semi_minor: uncertainty_m,
                orientation_major: 0,
            },
            confidence: confidence.min(100),
        },
        // POINT_UNCERTAINTY_CIRCLE and anything else default to the circle.
        _ => GeographicArea::PointUncertaintyCircle {
            point,
            uncertainty: uncertainty_m,
        },
    }
}

/// Negotiate a GAD shape against the consumer's `supportedGADShapes` (lmfd-04).
///
/// Defaults to `POINT_UNCERTAINTY_CIRCLE`. Upgrades to
/// `POINT_UNCERTAINTY_ELLIPSE` when the consumer advertises it (and either an
/// ellipse is wanted or the circle is not advertised).
pub fn negotiate_gad_shape(supported: Option<&[String]>, want_ellipse: bool) -> &'static str {
    let supports = |s: &str| supported.map(|v| v.iter().any(|x| x == s)).unwrap_or(false);
    if want_ellipse && supports(gad_shape::POINT_UNCERTAINTY_ELLIPSE) {
        gad_shape::POINT_UNCERTAINTY_ELLIPSE
    } else if supported.is_none() || supports(gad_shape::POINT_UNCERTAINTY_CIRCLE) {
        gad_shape::POINT_UNCERTAINTY_CIRCLE
    } else if supports(gad_shape::POINT) {
        gad_shape::POINT
    } else if supports(gad_shape::POINT_UNCERTAINTY_ELLIPSE) {
        gad_shape::POINT_UNCERTAINTY_ELLIPSE
    } else {
        gad_shape::POINT_UNCERTAINTY_CIRCLE
    }
}

/// TS 23.032 §6.1: encode latitude (degrees) to the 24-bit GAD value, 3 octets
/// big-endian. The MSB is the sign (0 = North, 1 = South); the remaining 23
/// bits encode `N = round(2^23 * |lat| / 90)`, capped at `2^23 - 1`.
pub fn encode_gad_latitude(lat_deg: f64) -> [u8; 3] {
    let mag = lat_deg.abs().min(90.0);
    let mut n = (mag / 90.0 * f64::from(1u32 << 23)).round() as u32;
    let max = (1u32 << 23) - 1;
    if n > max {
        n = max;
    }
    let sign = if lat_deg < 0.0 { 1u32 << 23 } else { 0 };
    let v = sign | n;
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

/// TS 23.032 §6.1: encode longitude (degrees) to the 24-bit two's-complement
/// GAD value, 3 octets big-endian. `X = round(2^24 * lon / 360)` clamped to
/// `[-2^23, 2^23 - 1]`.
pub fn encode_gad_longitude(lon_deg: f64) -> [u8; 3] {
    let lon = lon_deg.clamp(-180.0, 180.0);
    let mut x = (lon / 360.0 * f64::from(1u32 << 24)).round() as i32;
    let max = (1i32 << 23) - 1;
    let min = -(1i32 << 23);
    x = x.clamp(min, max);
    let u = (x as u32) & 0x00ff_ffff;
    [(u >> 16) as u8, (u >> 8) as u8, u as u8]
}

/// TS 23.032 §6.2: encode an uncertainty (metres) to its 7-bit code `k`, where
/// `r = C((1+x)^k - 1)` with `C = 10`, `x = 0.1`. Result clamped to `0..=127`.
pub fn encode_gad_uncertainty(r_m: f64) -> u8 {
    if r_m <= 0.0 {
        return 0;
    }
    const C: f64 = 10.0;
    const X: f64 = 0.1;
    let k = ((r_m / C + 1.0).ln() / (1.0 + X).ln()).round();
    k.clamp(0.0, 127.0) as u8
}

/// Inverse of [`encode_gad_uncertainty`]: TS 23.032 §6.2 `r = C((1+x)^k - 1)`.
pub fn decode_gad_uncertainty(k: u8) -> f64 {
    const C: f64 = 10.0;
    const X: f64 = 0.1;
    C * ((1.0 + X).powi(i32::from(k)) - 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- TS 23.032 byte-vector tests (lmfd-LIB-03 acceptance) ---------------

    #[test]
    fn test_encode_gad_latitude_vectors() {
        assert_eq!(encode_gad_latitude(0.0), [0x00, 0x00, 0x00]);
        // 45 deg N -> 2^23 * 0.5 = 0x400000
        assert_eq!(encode_gad_latitude(45.0), [0x40, 0x00, 0x00]);
        // 45 deg S -> sign bit set
        assert_eq!(encode_gad_latitude(-45.0), [0xC0, 0x00, 0x00]);
        // 90 deg N saturates to 2^23 - 1
        assert_eq!(encode_gad_latitude(90.0), [0x7F, 0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_gad_longitude_vectors() {
        assert_eq!(encode_gad_longitude(0.0), [0x00, 0x00, 0x00]);
        // 45 deg E -> 2^24 * 45/360 = 0x200000
        assert_eq!(encode_gad_longitude(45.0), [0x20, 0x00, 0x00]);
        // 90 deg E -> 0x400000
        assert_eq!(encode_gad_longitude(90.0), [0x40, 0x00, 0x00]);
        // 45 deg W -> two's complement of 0x200000 = 0xE00000
        assert_eq!(encode_gad_longitude(-45.0), [0xE0, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_gad_uncertainty_roundtrip() {
        assert_eq!(encode_gad_uncertainty(0.0), 0);
        // k=1 -> r = 10*(1.1 - 1) = 1.0 m exactly
        assert_eq!(encode_gad_uncertainty(1.0), 1);
        assert!((decode_gad_uncertainty(1) - 1.0).abs() < 1e-9);
        // 100 m -> k=25 -> decode ~98.35 m
        let k = encode_gad_uncertainty(100.0);
        assert_eq!(k, 25);
        assert!((decode_gad_uncertainty(k) - 98.347).abs() < 0.01);
        assert_eq!(encode_gad_uncertainty(1.0e9), 127); // saturates
    }

    // -- to_gad / shape tests (lmfd-LIB-03 + lmfd-04 acceptance) ------------

    #[test]
    fn test_to_gad_default_circle_shape() {
        let geo = to_gad(37.5, -122.25, 50.0, 95, gad_shape::POINT_UNCERTAINTY_CIRCLE);
        assert_eq!(geo.shape(), "POINT_UNCERTAINTY_CIRCLE");
        let v = serde_json::to_value(&geo).unwrap();
        assert_eq!(v["shape"], "POINT_UNCERTAINTY_CIRCLE");
        assert_eq!(v["point"]["lat"], 37.5);
        assert_eq!(v["point"]["lon"], -122.25);
        assert_eq!(v["uncertainty"], 50.0);
    }

    #[test]
    fn test_to_gad_ellipse_shape() {
        let geo = to_gad(1.0, 2.0, 30.0, 90, gad_shape::POINT_UNCERTAINTY_ELLIPSE);
        assert_eq!(geo.shape(), "POINT_UNCERTAINTY_ELLIPSE");
        let v = serde_json::to_value(&geo).unwrap();
        assert_eq!(v["shape"], "POINT_UNCERTAINTY_ELLIPSE");
        assert_eq!(v["uncertaintyEllipse"]["semiMajor"], 30.0);
        assert_eq!(v["confidence"], 90);
    }

    #[test]
    fn test_to_gad_unknown_shape_falls_back_to_circle() {
        let geo = to_gad(0.0, 0.0, 10.0, 95, "NOT_A_SHAPE");
        assert_eq!(geo.shape(), "POINT_UNCERTAINTY_CIRCLE");
    }

    #[test]
    fn test_geographic_area_roundtrip() {
        let geo = to_gad(12.34, 56.78, 25.0, 80, gad_shape::POINT_UNCERTAINTY_ELLIPSE);
        let json = serde_json::to_string(&geo).unwrap();
        let back: GeographicArea = serde_json::from_str(&json).unwrap();
        assert_eq!(geo, back);
    }

    #[test]
    fn test_negotiate_gad_shape() {
        // No advertised shapes -> default circle.
        assert_eq!(negotiate_gad_shape(None, false), "POINT_UNCERTAINTY_CIRCLE");
        // Ellipse wanted and advertised -> ellipse.
        let both = vec![
            "POINT_UNCERTAINTY_ELLIPSE".to_string(),
            "POINT_UNCERTAINTY_CIRCLE".to_string(),
        ];
        assert_eq!(
            negotiate_gad_shape(Some(&both), true),
            "POINT_UNCERTAINTY_ELLIPSE"
        );
        // Ellipse wanted but only circle advertised -> circle.
        let circle = vec!["POINT_UNCERTAINTY_CIRCLE".to_string()];
        assert_eq!(
            negotiate_gad_shape(Some(&circle), true),
            "POINT_UNCERTAINTY_CIRCLE"
        );
        // Only POINT advertised -> POINT.
        let point = vec!["POINT".to_string()];
        assert_eq!(negotiate_gad_shape(Some(&point), false), "POINT");
    }

    // -- InputData parse + ecgi/ncgi exclusion (lmfd-03 acceptance) ---------

    #[test]
    fn test_input_data_typed_parse() {
        let body = r#"{
            "externalClientType": "EMERGENCY_SERVICES",
            "correlationID": "corr-1",
            "amfId": "amf-abc",
            "supi": "imsi-001010000000001",
            "locationQoS": { "hAccuracy": 50.0, "verticalRequested": true },
            "supportedGADShapes": ["POINT_UNCERTAINTY_ELLIPSE", "POINT_UNCERTAINTY_CIRCLE"],
            "ldrType": "UE_AVAILABLE",
            "someFutureUnknownIe": { "x": 1 }
        }"#;
        let input: InputData = serde_json::from_str(body).unwrap();
        assert_eq!(input.correlation_id.as_deref(), Some("corr-1"));
        assert_eq!(input.supi.as_deref(), Some("imsi-001010000000001"));
        assert_eq!(input.location_qos.as_ref().unwrap().h_accuracy, Some(50.0));
        assert_eq!(
            input.location_qos.as_ref().unwrap().vertical_requested,
            Some(true)
        );
        assert_eq!(input.supported_gad_shapes.as_ref().unwrap().len(), 2);
        // Unknown IE tolerated; ecgi/ncgi absent.
        assert!(input.ecgi.is_none());
        assert!(input.ncgi.is_none());
    }

    #[test]
    fn test_input_data_ecgi_present() {
        let body = r#"{
            "ecgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "eutraCellId": "0000001" }
        }"#;
        let input: InputData = serde_json::from_str(body).unwrap();
        assert!(input.ecgi.is_some());
        assert!(input.ncgi.is_none());
    }

    #[test]
    fn test_input_data_both_ecgi_ncgi_parse_then_excluded() {
        // serde itself does not enforce `not: [ecgi, ncgi]`; the handler does.
        // This verifies both are observable so the handler can reject them.
        let body = r#"{
            "ecgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "eutraCellId": "0000001" },
            "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "nrCellId": "000000001" }
        }"#;
        let input: InputData = serde_json::from_str(body).unwrap();
        assert!(input.ecgi.is_some() && input.ncgi.is_some());
    }

    // -- LocationDataExt shape (lmfd-02 acceptance) ------------------------

    #[test]
    fn test_location_data_ext_roundtrip() {
        let resp = LocationDataExt {
            location_data: LocationData {
                location_estimate: to_gad(1.0, 2.0, 30.0, 95, gad_shape::POINT_UNCERTAINTY_CIRCLE),
                accuracy_fulfilment_indicator: Some(accuracy_fulfilment::FULFILLED.to_string()),
                age_of_location_estimate: Some(0),
                positioning_data_list: Some(vec![PositioningMethodAndUsage {
                    method: positioning_method::ECID.to_string(),
                    mode: "CONVENTIONAL".to_string(),
                    usage: "SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION".to_string(),
                }]),
                altitude: None,
                barometric_pressure: None,
                velocity_estimate: None,
                civic_address: None,
            },
            add_location_data: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        // locationEstimate carries a shape discriminator (flattened at top level).
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["locationEstimate"]["shape"], "POINT_UNCERTAINTY_CIRCLE");
        assert_eq!(
            v["accuracyFulfilmentIndicator"],
            "REQUESTED_ACCURACY_FULFILLED"
        );
        let back: LocationDataExt = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }
}
