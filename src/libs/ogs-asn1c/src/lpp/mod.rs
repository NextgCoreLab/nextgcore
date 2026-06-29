//! LPP codec — LTE/NR Positioning Protocol (3GPP TS 37.355), UNALIGNED PER,
//! LMF (location server) <-> UE (target device).
//!
//! Built on the standalone UPER codepath ([`crate::uper`]); the APER path
//! ([`crate::per`]) used by every NF's live wire is never touched. LPP is
//! specified with the UNALIGNED PER variant of X.691, hence the dedicated
//! encoder/decoder.
//!
//! # v1 FOUNDATION scope (Wave-3 lmfd-LIB-02b / LIB-02c / LIB-02d)
//!
//! This covers the message envelope, the capability-transfer bodies, and the
//! complete E-CID location loop:
//!
//! * [`types`] — transaction-management envelope primitives (`Initiator`,
//!   `TransactionNumber`, `SequenceNumber`, `LppTransactionId`,
//!   `Acknowledgement`).
//! * [`message`] — `LppMessage` + `LppMessageBody`/`MessageBodyC1` framing
//!   (request / provide capabilities + request / provide location information).
//! * [`capabilities`] — `RequestCapabilities`/`ProvideCapabilities` and the
//!   per-method capability containers (`CommonIEs*Capabilities`,
//!   `ECID-*Capabilities`).
//! * [`ecid`] — `ECID-RequestLocationInformation`,
//!   `ECID-ProvideLocationInformation`, `ECID-SignalMeasurementInformation`,
//!   `MeasuredResultsList`/`MeasuredResultsElement`, and `ECID-Error`.
//!
//! Assistance data, A-GNSS, OTDOA, and the other positioning methods are
//! carried by follow-on chunks; where they appear as root optionals they are
//! modeled UNSUPPORTED-ABSENT (never emitted; rejected on decode).
//!
//! There is no golden LPP wire vector in-repo and no network egress, so the
//! reference vector in [`message`] is hand-derived bit-by-bit from X.691 and is
//! self-attesting.

pub mod capabilities;
pub mod ecid;
pub mod message;
pub mod nr_dl_tdoa;
pub mod types;

pub use capabilities::*;
pub use ecid::*;
pub use message::*;
pub use nr_dl_tdoa::*;
pub use types::*;
