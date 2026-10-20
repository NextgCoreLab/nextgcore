# sctp-proto 0.6.0 — nextgsim patch (#220)

**Upstream:** crates.io `sctp-proto` 0.6.0 (webrtc-rs, git sha
`0f3be0800602d934c84f4e86e903187ea3ae5708`), copied verbatim from the cargo
registry, minus `.github/`, `Cargo.lock`, `.gitignore`, `.cargo_vcs_info.json`
and `Cargo.toml.orig`. Licences (MIT / Apache-2.0) kept.

**Why vendored.** `PayloadProtocolIdentifier` only names the five WebRTC PPIDs
(50, 51, 53, 56, 57). `From<u32>` maps every other value to `Unknown`, and
`Unknown` has the implicit discriminant 58, which is what `put_u32(... as u32)`
writes. So NGAP (PPID 60, TS 38.412 §7) and S1AP (PPID 18, TS 36.412 §7) were
sent as 58, and a received 60 or 18 could not be told apart. The latest release,
0.10.7, has the identical enum, so upgrading would not help. A correct fix has
to change the crate.

**The patch (the only change from upstream):**

- `PayloadProtocolIdentifier` gains `Other(u32)`, which carries any non-WebRTC
  PPID verbatim. `Unknown` now means PPID 0, "not specified by the upper layer"
  (RFC 9260 §3.3.1), and stays the `Default`.
- `From<u32>`: 0 → `Unknown`, the WebRTC values as before, anything else →
  `Other(v)`. A new `From<PayloadProtocolIdentifier> for u32` is the inverse.
- The DATA chunk writer and one `trace!` in `association/mod.rs` use
  `u32::from(..)` instead of `as u32`, which no longer applies to a data-carrying
  enum.
- `#[repr(C)]` and the explicit discriminants are removed, since the enum now has
  a data variant. `Eq` is derived.

**Wire effect.** A caller-chosen PPID goes out exactly as given. The one other
change: a stream written with the default (`Unknown`) payload type now sends 0
instead of 58. nextgsim always passes an explicit PPID.

**Peers.** An unpatched sctp-proto peer, such as nextgcore's userspace server,
decodes 60 or 18 as its own `Unknown` and keeps working. Its sends still carry
58, which this side now reports truthfully as 58.

**Kept out of the workspace** (`exclude` in the root `Cargo.toml`), so its tests
and lints are not counted as nextgsim's. Its own suite passes with the patch:
`cargo test --manifest-path vendor/sctp-proto/Cargo.toml`, 105 passed.

**Diff against upstream:**

```diff
--- a/src/chunk/chunk_payload_data.rs	2026-10-19 22:44:50.113642539 +0000
+++ vendor/sctp-proto/src/chunk/chunk_payload_data.rs	2026-10-19 22:46:16.554187415 +0000
@@ -11,17 +11,24 @@
 /// PayloadProtocolIdentifier is an enum for DataChannel payload types
 // PayloadProtocolIdentifier enums
 // <https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25>
-#[derive(Debug, Copy, Clone, PartialEq)]
-#[repr(C)]
-#[derive(Default)]
+//
+// nextgsim patch (#220): upstream maps every PPID outside the five WebRTC values
+// to `Unknown`, whose implicit discriminant serialises as 58, so NGAP (60) and
+// S1AP (18) went on the wire as 58. `Other(u32)` carries any other PPID
+// verbatim, and `Unknown` now means the RFC 9260 §3.3.1 value 0 ("not
+// specified by the upper layer"). See vendor/sctp-proto/NEXTGSIM-PATCH.md.
+#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
 pub enum PayloadProtocolIdentifier {
-    Dcep = 50,
-    String = 51,
-    Binary = 53,
-    StringEmpty = 56,
-    BinaryEmpty = 57,
+    Dcep,
+    String,
+    Binary,
+    StringEmpty,
+    BinaryEmpty,
+    /// PPID 0: not specified by the upper layer (RFC 9260 §3.3.1).
     #[default]
     Unknown,
+    /// Any other PPID, carried verbatim (e.g. S1AP 18, NGAP 60).
+    Other(u32),
 }
 
 impl fmt::Display for PayloadProtocolIdentifier {
@@ -32,7 +39,8 @@
             PayloadProtocolIdentifier::Binary => "WebRTC Binary",
             PayloadProtocolIdentifier::StringEmpty => "WebRTC String (Empty)",
             PayloadProtocolIdentifier::BinaryEmpty => "WebRTC Binary (Empty)",
-            _ => "Unknown Payload Protocol Identifier",
+            PayloadProtocolIdentifier::Other(v) => return write!(f, "PPID {}", v),
+            PayloadProtocolIdentifier::Unknown => "Unknown Payload Protocol Identifier",
         };
         write!(f, "{}", s)
     }
@@ -46,7 +54,22 @@
             53 => PayloadProtocolIdentifier::Binary,
             56 => PayloadProtocolIdentifier::StringEmpty,
             57 => PayloadProtocolIdentifier::BinaryEmpty,
-            _ => PayloadProtocolIdentifier::Unknown,
+            0 => PayloadProtocolIdentifier::Unknown,
+            other => PayloadProtocolIdentifier::Other(other),
+        }
+    }
+}
+
+impl From<PayloadProtocolIdentifier> for u32 {
+    fn from(v: PayloadProtocolIdentifier) -> u32 {
+        match v {
+            PayloadProtocolIdentifier::Dcep => 50,
+            PayloadProtocolIdentifier::String => 51,
+            PayloadProtocolIdentifier::Binary => 53,
+            PayloadProtocolIdentifier::StringEmpty => 56,
+            PayloadProtocolIdentifier::BinaryEmpty => 57,
+            PayloadProtocolIdentifier::Unknown => 0,
+            PayloadProtocolIdentifier::Other(other) => other,
         }
     }
 }
@@ -223,7 +246,7 @@
         writer.put_u32(self.tsn);
         writer.put_u16(self.stream_identifier);
         writer.put_u16(self.stream_sequence_number);
-        writer.put_u32(self.payload_type as u32);
+        writer.put_u32(u32::from(self.payload_type));
         writer.extend_from_slice(&self.user_data);
 
         Ok(writer.len())
--- a/src/association/mod.rs	2006-07-24 01:21:28.000000000 +0000
+++ vendor/sctp-proto/src/association/mod.rs	2026-10-19 22:44:50.143642730 +0000
@@ -2632,7 +2632,7 @@
             trace!(
                 "[{}] sending ppi={} tsn={} ssn={} sent={} len={} ({},{})",
                 self.side,
-                c.payload_type as u32,
+                u32::from(c.payload_type),
                 c.tsn,
                 c.stream_sequence_number,
                 c.nsent,
```
