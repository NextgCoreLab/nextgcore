#!/usr/bin/env python3
"""H7 golden-vector derivation B — independent from-scratch UPER recompute.

Implements the needed ITU-T X.691 (UNALIGNED PER) rules directly from the
standard's clauses, then builds the A-GNSS LPP assistance-data messages
(3GPP TS 37.355 v16/j20 ASN.1, §6.5.2) bit by bit. Written WITHOUT reading the
Rust encoder or derivation-A's numeric bit tables — only from X.691 + the ASN.1
productions cited in the a_gnss modules' doc comments.

UPER differences honoured (X.691): NO alignment ever (no length-of-length octet
forms; constrained ints are pure minimal bit-fields at any range); only the
final message is zero-padded to a whole octet.
"""


class Bits:
    def __init__(self):
        self.b = []

    def bit(self, x):
        self.b.append(1 if x else 0)

    def nbits(self, value, n):
        assert value >= 0, value
        assert value < (1 << n), (value, n)
        for i in range(n - 1, -1, -1):
            self.b.append((value >> i) & 1)

    @staticmethod
    def bits_needed(rng):
        # X.691 UNALIGNED constrained whole number: minimum bits for the range.
        if rng <= 1:
            return 0
        return (rng - 1).bit_length()

    def constrained_int(self, value, lo, hi):
        """X.691 11.5 (UNALIGNED) constrained whole number."""
        rng = hi - lo + 1
        off = value - lo
        assert 0 <= off < rng, (value, lo, hi, off, rng)
        n = self.bits_needed(rng)
        if n:
            self.nbits(off, n)

    def enumerated(self, index, root_lo, root_hi, extensible):
        """X.691 14 ENUMERATED, UNALIGNED. index assumed in root here."""
        if extensible:
            self.bit(0)  # not in extension
        self.constrained_int(index, root_lo, root_hi)

    def choice_index(self, index, num_alts, extensible):
        """X.691 23 CHOICE index, UNALIGNED. index assumed in root here."""
        if extensible:
            self.bit(0)  # in root
        self.constrained_int(index, 0, num_alts - 1)

    def seq_preamble(self, ext_present, optionals):
        """X.691 18 SEQUENCE preamble. ext_present=None => not extensible."""
        if ext_present is not None:
            self.bit(ext_present)
        for o in optionals:
            self.bit(1 if o else 0)

    def bitstring_fixed(self, value, n):
        """BIT STRING (SIZE(n)) fixed, X.691 16 — content bits, no length."""
        self.nbits(value, n)

    def out(self):
        bb = list(self.b)
        while len(bb) % 8:
            bb.append(0)
        out = bytearray()
        for i in range(0, len(bb), 8):
            v = 0
            for x in bb[i:i + 8]:
                v = (v << 1) | x
            out.append(v)
        return bytes(out), len(self.b)


# ---------------------------------------------------------------------------
# Spine primitives
# ---------------------------------------------------------------------------
def gnss_id(w, idx):
    # GNSS-ID ::= SEQUENCE { gnss-id ENUMERATED{gps..bds,...} }  (extensible SEQ)
    w.seq_preamble(0, [])                 # extensible SEQ, no optionals
    w.enumerated(idx, 0, 5, True)         # 6 root values


def sbas_id(w, idx):
    w.seq_preamble(0, [])
    w.enumerated(idx, 0, 3, True)         # 4 root values


def gnss_signal_id(w, val):
    # GNSS-SignalID ::= SEQUENCE { gnss-SignalID INTEGER(0..7), ... }
    w.seq_preamble(0, [])
    w.constrained_int(val, 0, 7)


def sv_id(w, sat):
    # SV-ID ::= SEQUENCE { satellite-id INTEGER(0..63) }  (extensible SEQ)
    w.seq_preamble(0, [])
    w.constrained_int(sat, 0, 63)


def gnss_system_time(w, id_idx, day, tod, frac, notif):
    # GNSS-SystemTime ::= SEQUENCE { gnss-TimeID GNSS-ID, gnss-DayNumber(0..32767),
    #   gnss-TimeOfDay(0..86399), gnss-TimeOfDayFrac-msec(0..999) OPT,
    #   notificationOfLeapSecond BIT STRING(SIZE(2)) OPT, gps-TOW-Assist OPT, ... }
    w.seq_preamble(0, [frac is not None, notif is not None, False])
    gnss_id(w, id_idx)
    w.constrained_int(day, 0, 32767)
    w.constrained_int(tod, 0, 86399)
    if frac is not None:
        w.constrained_int(frac, 0, 999)
    if notif is not None:
        w.bitstring_fixed(notif, 2)


# ---------------------------------------------------------------------------
# VECTOR 1: A-GNSS-ProvideAssistanceData (spine/envelope)
#   common absent; generic present with one element {gnss-ID=sbas, sbas-ID=egnos}
# ---------------------------------------------------------------------------
def vector1():
    w = Bits()
    # A-GNSS-ProvideAssistanceData ::= SEQUENCE {common OPT, generic OPT, error OPT, ...}
    w.seq_preamble(0, [False, True, False])   # ext0, common=0, generic=1, error=0
    # GNSS-GenericAssistData ::= SEQUENCE(SIZE(1..16)) OF element  -> length det
    w.constrained_int(1, 1, 16)               # one element
    # GNSS-GenericAssistDataElement: extensible SEQ, gnss-ID mandatory + 10 opts
    # opts = [sbas,timeModels,diff,nav,rti,dataBit,acq,almanac,utc,aux]
    w.seq_preamble(0, [True, False, False, False, False, False, False, False, False, False])
    gnss_id(w, 1)                             # sbas = index 1
    sbas_id(w, 1)                             # egnos = index 1
    return w.out()


# ---------------------------------------------------------------------------
# VECTOR 2: GNSS-ReferenceTime
#   system-time(galileo, day=100, tod=5000, frac=500, notif absent),
#   referenceTimeUnc=63, cells absent
# ---------------------------------------------------------------------------
def vector2():
    w = Bits()
    # GNSS-ReferenceTime ::= SEQUENCE { gnss-SystemTime, referenceTimeUnc(0..127) OPT,
    #   gnss-ReferenceTimeForCells OPT, ... }
    w.seq_preamble(0, [True, False])          # unc present, cells absent
    gnss_system_time(w, 3, 100, 5000, 500, None)  # galileo = index 3
    w.constrained_int(63, 0, 127)             # referenceTimeUnc
    return w.out()


# ---------------------------------------------------------------------------
# VECTOR 3: GNSS-NavigationModel (one satellite, one Keplerian set)
# ---------------------------------------------------------------------------
def nav_clock(w, toc, af2, af1, af0, tgd):
    # NAV-ClockModel ::= SEQUENCE { navToc(0..37799), navaf2(-128..127),
    #   navaf1(-32768..32767), navaf0(-2097152..2097151), navTgd(-128..127), ... }
    w.seq_preamble(0, [])
    w.constrained_int(toc, 0, 37799)
    w.constrained_int(af2, -128, 127)
    w.constrained_int(af1, -32768, 32767)
    w.constrained_int(af0, -2097152, 2097151)
    w.constrained_int(tgd, -128, 127)


def keplerian(w, k):
    # NavModelKeplerianSet ::= SEQUENCE { 16 INTEGER fields, ... }
    w.seq_preamble(0, [])
    w.constrained_int(k['toe'], 0, 16383)
    w.constrained_int(k['w'], -2147483648, 2147483647)
    w.constrained_int(k['delta_n'], -32768, 32767)
    w.constrained_int(k['m0'], -2147483648, 2147483647)
    w.constrained_int(k['omega_dot'], -8388608, 8388607)
    w.constrained_int(k['e'], 0, 4294967295)
    w.constrained_int(k['i_dot'], -8192, 8191)
    w.constrained_int(k['a_power_half'], 0, 4294967295)
    w.constrained_int(k['i0'], -2147483648, 2147483647)
    w.constrained_int(k['omega0'], -2147483648, 2147483647)
    w.constrained_int(k['crs'], -32768, 32767)
    w.constrained_int(k['cis'], -32768, 32767)
    w.constrained_int(k['cus'], -32768, 32767)
    w.constrained_int(k['crc'], -32768, 32767)
    w.constrained_int(k['cic'], -32768, 32767)
    w.constrained_int(k['cuc'], -32768, 32767)


def vector3():
    w = Bits()
    kep = dict(toe=12345, w=-1000000000, delta_n=-12345, m0=2000000000,
               omega_dot=-8388608, e=4000000000, i_dot=8191,
               a_power_half=4294967295, i0=-2147483648, omega0=2147483647,
               crs=-32768, cis=32767, cus=-1, crc=100, cic=-100, cuc=0)
    # GNSS-NavigationModel ::= SEQUENCE { nonBroadcastIndFlag(0..1),
    #   gnss-SatelliteList, ... }
    w.seq_preamble(0, [])
    w.constrained_int(1, 0, 1)                # nonBroadcastIndFlag = 1
    # GNSS-NavModelSatelliteList ::= SEQUENCE(SIZE(1..64)) OF element
    w.constrained_int(1, 1, 64)               # one satellite
    # GNSS-NavModelSatelliteElement ::= SEQUENCE { svID, svHealth BIT STRING(8),
    #   iod BIT STRING(11), gnss-ClockModel, gnss-OrbitModel, ... }
    w.seq_preamble(0, [])
    sv_id(w, 42)
    w.bitstring_fixed(0b10100110, 8)          # svHealth = [1,0,1,0,0,1,1,0]
    w.bitstring_fixed(0b11001010011, 11)      # iod = [1,1,0,0,1,0,1,0,0,1,1]
    # GNSS-ClockModel CHOICE: nav-ClockModel = root alt index 1 of 5, extensible
    w.choice_index(1, 5, True)
    nav_clock(w, 37799, -128, 12345, -2097152, 127)
    # GNSS-OrbitModel CHOICE: keplerianSet = root alt index 0 of 5, extensible
    w.choice_index(0, 5, True)
    keplerian(w, kep)
    return w.out()


# ---------------------------------------------------------------------------
# VECTOR 4: GNSS-AcquisitionAssistance (one satellite)
# ---------------------------------------------------------------------------
def acq_element(w, e):
    # GNSS-AcquisitionAssistElement ::= SEQUENCE { svID, doppler0(-2048..2047),
    #   doppler1(0..63), dopplerUncertainty(0..4), codePhase(0..1022),
    #   intCodePhase(0..127), codePhaseSearchWindow(0..31), azimuth(0..511),
    #   elevation(0..127), ... }
    w.seq_preamble(0, [])
    sv_id(w, e['sv'])
    w.constrained_int(e['doppler0'], -2048, 2047)
    w.constrained_int(e['doppler1'], 0, 63)
    w.constrained_int(e['du'], 0, 4)
    w.constrained_int(e['code_phase'], 0, 1022)
    w.constrained_int(e['int_cp'], 0, 127)
    w.constrained_int(e['csw'], 0, 31)
    w.constrained_int(e['azimuth'], 0, 511)
    w.constrained_int(e['elevation'], 0, 127)


def vector4():
    w = Bits()
    el = dict(sv=17, doppler0=-1500, doppler1=42, du=3, code_phase=900,
              int_cp=100, csw=20, azimuth=400, elevation=90)
    # GNSS-AcquisitionAssistance ::= SEQUENCE { gnss-SignalID,
    #   gnss-AcquisitionAssistList, ..., confidence-r10 OPT }
    w.seq_preamble(0, [])                     # extensible SEQ, no root opts
    gnss_signal_id(w, 5)
    # GNSS-AcquisitionAssistList ::= SEQUENCE(SIZE(1..64)) OF element
    w.constrained_int(1, 1, 64)               # one satellite
    acq_element(w, el)
    return w.out()


for name, fn in [("Vector 1 (ProvideAssistanceData spine)", vector1),
                 ("Vector 2 (GNSS-ReferenceTime)", vector2),
                 ("Vector 3 (GNSS-NavigationModel)", vector3),
                 ("Vector 4 (GNSS-AcquisitionAssistance)", vector4)]:
    data, nbits = fn()
    print(f"{name}: {nbits} bits -> {len(data)} octets")
    print("   ", " ".join(f"{b:02X}" for b in data))
