//! #1142: the answer to an out-of-the-blue SCTP packet (RFC 9260 §8.4).
//!
//! An out-of-the-blue (OOTB) packet is one the endpoint cannot match to any
//! association. A restarted AMF gets exactly these: the gNB keeps sending on the
//! association the AMF had before it restarted. §8.4 has the receiver answer most of
//! them with an ABORT:
//! - the ABORT has the T bit set;
//! - its Verification Tag is the one from the received packet.
//!
//! The peer then learns at once that its association is gone and sets up a new one
//! (for NGAP, a new NG Setup). It does not have to wait out
//! Association.Max.Retrans, which takes minutes.
//!
//! The rules, in order (§8.4):
//! 1. A packet that fails the checksum is discarded silently (§6.8). The unicast
//!    check of rule 1 does not apply to SCTP over UDP.
//! 2. A packet that contains an ABORT is discarded.
//! 3. An INIT, or 4. a COOKIE ECHO, is the association setup's business, not this.
//! 5. A SHUTDOWN ACK is answered with a SHUTDOWN COMPLETE, T bit set.
//! 6. A SHUTDOWN COMPLETE is discarded.
//! 7. A COOKIE ACK is discarded. So is an ERROR (possibly "Stale Cookie"); the
//!    stale-cookie case is the only one the rule names, and an ERROR of any other
//!    cause answers nothing an ABORT would improve.
//! 8. Anything else is answered with an ABORT, T bit set.

/// Chunk types (RFC 9260 §3.2).
const CT_INIT: u8 = 1;
const CT_ABORT: u8 = 6;
const CT_SHUTDOWN_ACK: u8 = 8;
const CT_ERROR: u8 = 9;
const CT_COOKIE_ECHO: u8 = 10;
const CT_COOKIE_ACK: u8 = 11;
const CT_SHUTDOWN_COMPLETE: u8 = 14;

/// The T bit of ABORT and SHUTDOWN COMPLETE (§3.3.7, §3.3.13): "the sender filled in
/// the Verification Tag expected by the peer" is NOT set; set means the tag is the
/// received one ("reflected").
const FLAG_T: u8 = 0x01;

const COMMON_HEADER_LEN: usize = 12;

/// CRC-32C (Castagnoli), as SCTP uses it (RFC 9260 Appendix A).
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0x82F6_3B78 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// The checksum of `packet` as SCTP places it: computed with the checksum field zero,
/// stored least significant byte first (Appendix A).
fn checksum(packet: &[u8]) -> [u8; 4] {
    let mut copy = packet.to_vec();
    copy[8..12].fill(0);
    crc32c(&copy).to_le_bytes()
}

/// Whether `packet` carries a valid SCTP checksum.
pub fn checksum_ok(packet: &[u8]) -> bool {
    packet.len() >= COMMON_HEADER_LEN && packet[8..12] == checksum(packet)
}

/// The chunk types of `packet`, in order; `None` when the chunks do not parse.
fn chunk_types(packet: &[u8]) -> Option<Vec<u8>> {
    let mut types = Vec::new();
    let mut off = COMMON_HEADER_LEN;
    while off < packet.len() {
        let header = packet.get(off..off + 4)?;
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if len < 4 || off + len > packet.len() {
            return None;
        }
        types.push(header[0]);
        off += len.div_ceil(4) * 4;
    }
    (!types.is_empty()).then_some(types)
}

/// A packet of one chunk of `chunk_type` with the T bit, answering `received`: ports
/// swapped, the received Verification Tag reflected.
fn reflected(received: &[u8], chunk_type: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMON_HEADER_LEN + 4);
    out.extend_from_slice(&received[2..4]); // source port: the one it was sent to
    out.extend_from_slice(&received[0..2]); // destination port: the sender's
    out.extend_from_slice(&received[4..8]); // the received Verification Tag (T bit)
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&[chunk_type, FLAG_T, 0, 4]);
    let sum = checksum(&out);
    out[8..12].copy_from_slice(&sum);
    out
}

/// What to send back for the out-of-the-blue `packet`, if anything (RFC 9260 §8.4).
pub fn ootb_response(packet: &[u8]) -> Option<Vec<u8>> {
    if !checksum_ok(packet) {
        return None;
    }
    let types = chunk_types(packet)?;
    if types.contains(&CT_ABORT) {
        return None;
    }
    match types[0] {
        CT_INIT | CT_COOKIE_ECHO => None,
        CT_SHUTDOWN_ACK => Some(reflected(packet, CT_SHUTDOWN_COMPLETE)),
        CT_SHUTDOWN_COMPLETE | CT_COOKIE_ACK | CT_ERROR => None,
        _ => Some(reflected(packet, CT_ABORT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet from port 5000 to 38412 under `vtag` with these (type, flags,
    /// value) chunks, checksummed.
    fn packet(vtag: u32, chunks: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&5000u16.to_be_bytes());
        p.extend_from_slice(&38412u16.to_be_bytes());
        p.extend_from_slice(&vtag.to_be_bytes());
        p.extend_from_slice(&[0; 4]);
        for (t, f, v) in chunks {
            p.push(*t);
            p.push(*f);
            p.extend_from_slice(&((4 + v.len()) as u16).to_be_bytes());
            p.extend_from_slice(v);
            while p.len() % 4 != 0 {
                p.push(0);
            }
        }
        let sum = checksum(&p);
        p[8..12].copy_from_slice(&sum);
        p
    }

    /// RFC 3720 Appendix B.4 (iSCSI): CRC-32C of 32 zero octets is 0x8A9136AA.
    #[test]
    fn crc32c_is_castagnoli() {
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    /// §8.4 rule 8: a DATA (or SACK, HEARTBEAT) of an association the endpoint does
    /// not hold is answered with an ABORT, T bit set, the received tag reflected and
    /// the ports swapped, with a valid checksum.
    #[test]
    fn data_of_an_unknown_association_is_aborted_with_the_t_bit() {
        for t in [0u8, 3, 4] {
            let p = packet(
                0xDEAD_BEEF,
                &[(t, 0x03, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])],
            );
            let abort = ootb_response(&p).expect("an ABORT");
            assert_eq!(&abort[0..2], &p[2..4], "from the port it was sent to");
            assert_eq!(&abort[2..4], &p[0..2], "to the sender's port");
            assert_eq!(
                &abort[4..8],
                &0xDEAD_BEEFu32.to_be_bytes(),
                "the received tag"
            );
            assert_eq!(&abort[12..16], &[CT_ABORT, FLAG_T, 0, 4]);
            assert!(checksum_ok(&abort));
        }
    }

    /// §8.4 rules 2-7: what is NOT answered with an ABORT.
    #[test]
    fn the_rfc_exceptions_get_no_abort() {
        let shutdown_complete = ootb_response(&packet(7, &[(CT_SHUTDOWN_ACK, 0, &[])]))
            .expect("rule 5: SHUTDOWN COMPLETE");
        assert_eq!(
            &shutdown_complete[12..16],
            &[CT_SHUTDOWN_COMPLETE, FLAG_T, 0, 4]
        );
        for chunks in [
            vec![(CT_ABORT, 0, &[][..])],
            vec![(0, 0, &[1, 2, 3, 4][..]), (CT_ABORT, 1, &[][..])],
            vec![(CT_INIT, 0, &[0u8; 16][..])],
            vec![(CT_COOKIE_ECHO, 0, &[9u8; 8][..])],
            vec![(CT_SHUTDOWN_COMPLETE, 1, &[][..])],
            vec![(CT_COOKIE_ACK, 0, &[][..])],
            vec![(CT_ERROR, 0, &[0, 3, 0, 8, 0, 0, 0, 1][..])],
        ] {
            assert_eq!(ootb_response(&packet(7, &chunks)), None, "{chunks:?}");
        }
    }

    /// §6.8: a bad checksum, or chunks that do not parse, are discarded silently.
    #[test]
    fn a_corrupt_packet_gets_nothing() {
        let mut p = packet(7, &[(0, 3, &[1, 2, 3, 4])]);
        p[8] ^= 0xFF;
        assert_eq!(ootb_response(&p), None, "bad checksum");
        let mut q = packet(7, &[(0, 3, &[1, 2, 3, 4])]);
        q[14..16].copy_from_slice(&200u16.to_be_bytes());
        let sum = checksum(&q);
        q[8..12].copy_from_slice(&sum);
        assert_eq!(ootb_response(&q), None, "chunk length beyond the packet");
        assert_eq!(ootb_response(&[0u8; 5]), None, "too short");
    }
}
