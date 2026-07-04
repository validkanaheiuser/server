"""
cccd_setup.py — Populate cccd_cache.json by reading a real CCCD chip directly.

Usage (run on any machine connected to the CCCD chip via USB NFC reader or ADB):
  python cccd_setup.py --mrz                 # interactive MRZ input
  python cccd_setup.py --scan                # scan MRZ from CCCD via nfcpy
  python cccd_setup.py --adb                 # use Samsung phone via ADB + NFCGate

After this runs, cccd_config.json and cccd_cache.json are ready for serve mode.
Requires: pip install nfcpy pycryptodome     (for --scan or --mrz)
          adb in PATH                         (for --adb)
"""

import argparse
import hashlib
import json
import os
import sys
import struct
import re

# ─── Inline crypto (same as mod_cccd_cache.py) ───────────────────────────────
from Crypto.Cipher import DES, DES3

def _adjust_parity(b):
    out = bytearray(b)
    for i in range(len(out)):
        if bin(out[i]).count('1') % 2 == 0:
            out[i] ^= 1
    return bytes(out)

def _mrz_check_digit(s):
    weights = [7, 3, 1]
    total = 0
    for i, c in enumerate(s):
        if c.isdigit():   v = int(c)
        elif c.isalpha(): v = ord(c.upper()) - 55
        else:             v = 0
        total += v * weights[i % 3]
    return str(total % 10)

def _derive_key(seed16, counter):
    c = counter.to_bytes(4, 'big')
    return _adjust_parity(hashlib.sha1(seed16 + c).digest()[:16])

def _bac_keys(doc_number, dob, expiry):
    d = (doc_number + '<' * 9)[:9]
    mrz_info = d + _mrz_check_digit(d) + dob + _mrz_check_digit(dob) + expiry + _mrz_check_digit(expiry)
    seed = hashlib.sha1(mrz_info.encode('ascii')).digest()[:16]
    return _derive_key(seed, 1), _derive_key(seed, 2)

def _3des_cbc(key, iv, data, encrypt=True):
    c = DES3.new(key, DES3.MODE_CBC, iv)
    return c.encrypt(data) if encrypt else c.decrypt(data)

def _3des_ecb(key, block):
    return DES3.new(key, DES3.MODE_ECB).encrypt(block)

def _retail_mac(key, data):
    padded = data + b'\x80' + b'\x00' * ((-len(data) - 1) % 8)
    k1, k2 = key[:8], key[8:16]
    state = b'\x00' * 8
    for i in range(0, len(padded), 8):
        block = bytes(a ^ b for a, b in zip(state, padded[i:i+8]))
        state = DES.new(k1, DES.MODE_ECB).encrypt(block)
    state = DES.new(k2, DES.MODE_ECB).decrypt(state)
    return DES.new(k1, DES.MODE_ECB).encrypt(state)

def _pad80(data):
    p = data + b'\x80'
    p += b'\x00' * ((-len(p)) % 8)
    return p

def _sm_dec(ksenc, ssc, do87):
    iv = _3des_ecb(ksenc, ssc)
    ct = do87[1:]   # strip 0x01 padding indicator
    raw = _3des_cbc(ksenc, iv, ct, encrypt=False)
    i = len(raw) - 1
    while i >= 0 and raw[i] == 0x00: i -= 1
    return raw[:i] if i >= 0 and raw[i] == 0x80 else raw

def _parse_tlv(data):
    result, i = {}, 0
    while i < len(data):
        tag = data[i]; i += 1
        if i >= len(data): break
        ln = data[i]; i += 1
        if ln == 0x81:   ln = data[i]; i += 1
        elif ln == 0x82: ln = (data[i] << 8) | data[i+1]; i += 2
        result[tag] = data[i:i+ln]; i += ln
    return result


# ─── NFC reader (nfcpy) ───────────────────────────────────────────────────────

class NFCReader:
    """Thin wrapper around nfcpy for CCCD reading."""

    def __init__(self):
        try:
            import nfc
            self._nfc = nfc
        except ImportError:
            sys.exit("ERROR: nfcpy not installed. Run: pip install nfcpy")
        self._tag = None
        self._clf = None

    def connect(self):
        clf = self._nfc.ContactlessFrontend()
        clf.open('usb')
        self._clf = clf
        print("Waiting for CCCD chip...")

        def on_connect(tag):
            self._tag = tag
            return True

        clf.connect(rdwr={'on-connect': on_connect})
        print(f"Tag detected: {type(self._tag).__name__}")

    def transceive(self, apdu: bytes) -> bytes:
        if hasattr(self._tag, 'send_apdu'):
            return bytes(self._tag.send_apdu(*apdu[:4], apdu[5:]))
        resp = self._tag.transceive(apdu)
        return bytes(resp)

    def close(self):
        if self._clf:
            self._clf.close()


# ─── CCCD reader protocol ─────────────────────────────────────────────────────

MRTD_AID = bytes.fromhex('A0000002471001')

EF_FILES = {
    '011E': 'EF.COM',
    '0101': 'DG1',
    '0102': 'DG2',
    '0103': 'DG3',
    '0107': 'DG7',
    '010E': 'DG14',
    '010F': 'DG15',
    '011D': 'EF.SOD',
}

def _apdu(cla, ins, p1, p2, data=b'', le=None):
    apdu = bytes([cla, ins, p1, p2])
    if data:
        apdu += bytes([len(data)]) + data
    if le is not None:
        apdu += bytes([le])
    return apdu

def select_app(transport):
    resp = transport(_apdu(0x00, 0xA4, 0x04, 0x00, MRTD_AID, 0))
    return resp[-2:] == b'\x90\x00'

def get_challenge(transport):
    resp = transport(_apdu(0x00, 0x84, 0x00, 0x00, le=8))
    if resp[-2:] != b'\x90\x00':
        raise RuntimeError(f"GET CHALLENGE failed: {resp.hex()}")
    return resp[:8]

def external_authenticate(transport, kenc, kmac, chip_nonce):
    rnd_ifd = os.urandom(8)
    k_ifd   = os.urandom(16)
    s = rnd_ifd + chip_nonce + k_ifd
    eifd = _3des_cbc(kenc, b'\x00'*8, s)
    mifd = _retail_mac(kmac, eifd)
    resp = transport(_apdu(0x00, 0x82, 0x00, 0x00, eifd + mifd, 0x28))
    if resp[-2:] != b'\x90\x00':
        raise RuntimeError(f"EXTERNAL AUTH failed: {resp.hex()} (wrong MRZ?)")
    eic    = resp[:32]
    s_prime = _3des_cbc(kenc, b'\x00'*8, eic, encrypt=False)
    k_ic   = s_prime[16:32]
    ks_seed = bytes(a ^ b for a, b in zip(k_ifd, k_ic))
    ksenc  = _derive_key(ks_seed, 1)
    ksmac  = _derive_key(ks_seed, 2)
    ssc    = chip_nonce[4:] + rnd_ifd[4:]
    print(f"  BAC OK  KSenc={ksenc.hex()}")
    return ksenc, ksmac, ssc

def _inc_ssc(ssc):
    return (int.from_bytes(ssc, 'big') + 1).to_bytes(8, 'big')

def _encode_len(n):
    if n < 0x80:  return bytes([n])
    if n < 0x100: return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

def _retail_mac_raw(key, padded_msg):
    k1, k2 = key[:8], key[8:16]
    state = b'\x00' * 8
    for i in range(0, len(padded_msg), 8):
        block = bytes(a ^ b for a, b in zip(state, padded_msg[i:i+8]))
        state = DES.new(k1, DES.MODE_ECB).encrypt(block)
    state = DES.new(k2, DES.MODE_ECB).decrypt(state)
    return DES.new(k1, DES.MODE_ECB).encrypt(state)

def sm_select(transport, ksenc, ksmac, ssc, fid_bytes):
    ssc   = _inc_ssc(ssc)
    hdr   = bytes([0x0C, 0xA4, 0x02, 0x0C])
    iv    = _3des_ecb(ksenc, ssc)
    do87v = b'\x01' + _3des_cbc(ksenc, iv, _pad80(fid_bytes))
    do87  = b'\x87' + _encode_len(len(do87v)) + do87v
    m     = ssc + _pad80(hdr) + _pad80(do87)
    mac   = _retail_mac_raw(ksmac, m)
    body  = do87 + b'\x8E\x08' + mac
    resp  = transport(hdr + bytes([len(body)]) + body)
    ssc   = _inc_ssc(ssc)
    if resp[-2:] not in (b'\x90\x00', b'\x62\x82'):
        raise RuntimeError(f"SM SELECT failed: {resp.hex()}")
    return ssc

def sm_read_binary(transport, ksenc, ksmac, ssc, offset, length):
    ssc  = _inc_ssc(ssc)
    p1   = (offset >> 8) & 0x7F
    p2   = offset & 0xFF
    hdr  = bytes([0x0C, 0xB0, p1, p2])
    do97 = bytes([length & 0xFF])
    do97_tlv = b'\x97\x01' + do97
    m    = ssc + _pad80(hdr) + _pad80(do97_tlv)
    mac  = _retail_mac_raw(ksmac, m)
    body = do97_tlv + b'\x8E\x08' + mac
    resp = transport(hdr + bytes([len(body)]) + body)
    sw   = resp[-2:]
    if sw not in (b'\x90\x00', b'\x62\x82'):
        raise RuntimeError(f"SM READ BINARY failed at offset {offset}: {resp.hex()}")
    ssc = _inc_ssc(ssc)
    tlv = _parse_tlv(resp[:-2])
    do87 = tlv.get(0x87, b'')
    if not do87:
        return ssc, b''
    return ssc, _sm_dec(ksenc, ssc, do87)

def read_ef(transport, ksenc, ksmac, ssc, fid_hex, name):
    print(f"  Reading {name} ({fid_hex})...", end='', flush=True)
    try:
        ssc = sm_select(transport, ksenc, ksmac, ssc, bytes.fromhex(fid_hex))
        # Read first 4 bytes to get file length from TLV header
        ssc, hdr = sm_read_binary(transport, ksenc, ksmac, ssc, 0, 4)
        if not hdr:
            print(" (empty)")
            return ssc, b''
        if hdr[0] in (0x60, 0x61, 0x6F, 0x5F, 0x7F):
            if hdr[1] == 0x82:
                total_len = 4 + (hdr[2] << 8 | hdr[3])
            elif hdr[1] == 0x81:
                total_len = 3 + hdr[2]
            elif hdr[1] < 0x80:
                total_len = 2 + hdr[1]
            else:
                total_len = 256
        else:
            total_len = 256
        # Read full file in 0xEF-byte chunks
        data = hdr
        offset = len(hdr)
        while offset < total_len:
            chunk_size = min(0xEF, total_len - offset)
            ssc, chunk = sm_read_binary(transport, ksenc, ksmac, ssc, offset, chunk_size)
            if not chunk:
                break
            data += chunk
            offset += len(chunk)
        print(f" {len(data)} bytes")
        return ssc, data
    except Exception as e:
        print(f" SKIP ({e})")
        return ssc, b''

def read_all_dgs(transport, ksenc, ksmac, ssc):
    cache = {}
    for fid_hex, name in EF_FILES.items():
        ssc, data = read_ef(transport, ksenc, ksmac, ssc, fid_hex, name)
        if data:
            cache[fid_hex.upper()] = data
    return cache

def extract_mrz_from_dg1(dg1_bytes):
    """Parse DG1 to extract document number, DOB, expiry."""
    try:
        # DG1 structure: 61 len 5F1F len <MRZ data>
        data = dg1_bytes
        i = 0
        while i < len(data) - 1:
            if data[i] == 0x5F and data[i+1] == 0x1F:
                i += 2
                ln = data[i]; i += 1
                if ln == 0x81: ln = data[i]; i += 1
                mrz = data[i:i+ln].decode('ascii', errors='replace')
                # TD1: 3 lines of 30 chars; TD3 (passport): 2 lines of 44 chars
                if len(mrz) == 90:    # TD1
                    line2 = mrz[30:60]
                    doc_num = line2[0:9].rstrip('<')
                    dob     = line2[13:19]
                    expiry  = line2[20:26]
                    return doc_num, dob, expiry
                elif len(mrz) == 88:  # TD3 (passport)
                    line2 = mrz[44:88]
                    doc_num = mrz[0:9].rstrip('<')  # from line1
                    dob     = line2[0:6]
                    expiry  = line2[8:14]
                    return doc_num, dob, expiry
        return None, None, None
    except Exception:
        return None, None, None


# ─── MRZ input ────────────────────────────────────────────────────────────────

def prompt_mrz():
    print("\nNhập thông tin MRZ từ mặt trước thẻ CCCD:")
    print("  Số CCCD: 12 chữ số (VD: 042085000001)")
    doc_num_raw = input("  Số CCCD: ").strip()
    # CCCD MRZ uses first 9 chars of ID number
    doc_number = (doc_num_raw + '<' * 9)[:9]
    dob    = input("  Ngày sinh YYMMDD (VD: 850101): ").strip()
    expiry = input("  Hết hạn  YYMMDD (VD: 300101): ").strip()
    return doc_number, dob, expiry


# ─── Save results ─────────────────────────────────────────────────────────────

SERVER_DIR  = os.path.dirname(__file__)
CONFIG_FILE = os.path.join(SERVER_DIR, 'cccd_config.json')
CACHE_FILE  = os.path.join(SERVER_DIR, 'cccd_cache.json')

def save(doc_number, dob, expiry, cache):
    cfg = {
        'mode': 'serve',
        'doc_number': doc_number,
        'dob':        dob,
        'expiry':     expiry,
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

    raw = {k: v.hex() for k, v in cache.items()}
    with open(CACHE_FILE, 'w') as f:
        json.dump(raw, f, indent=2)

    print(f"\nĐã lưu:")
    print(f"  {CONFIG_FILE}  (mode=serve, doc={doc_number}, dob={dob}, exp={expiry})")
    print(f"  {CACHE_FILE}   ({len(cache)} files: {list(cache.keys())})")
    print("\nServer đã sẵn sàng serve mode. Chạy:")
    print("  PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python server.py cccd_cache")


# ─── Main ─────────────────────────────────────────────────────────────────────

def run_nfcpy(doc_number, dob, expiry):
    reader = NFCReader()
    reader.connect()
    try:
        kenc, kmac = _bac_keys(doc_number, dob, expiry)
        def transport(apdu):
            return reader.transceive(apdu)
        if not select_app(transport):
            raise RuntimeError("SELECT APPLICATION failed")
        print("  SELECT APP OK")
        chip_nonce = get_challenge(transport)
        ksenc, ksmac, ssc = external_authenticate(transport, kenc, kmac, chip_nonce)
        cache = read_all_dgs(transport, ksenc, ksmac, ssc)
    finally:
        reader.close()
    return cache

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mrz',  action='store_true', help='Enter MRZ manually, use nfcpy USB reader')
    ap.add_argument('--scan', action='store_true', help='Scan MRZ from CCCD via camera (not impl)')
    ap.add_argument('--doc',    help='Document number (9 chars)')
    ap.add_argument('--dob',    help='Date of birth YYMMDD')
    ap.add_argument('--expiry', help='Expiry date YYMMDD')
    args = ap.parse_args()

    if args.doc and args.dob and args.expiry:
        doc_number = (args.doc + '<' * 9)[:9]
        dob, expiry = args.dob, args.expiry
    else:
        doc_number, dob, expiry = prompt_mrz()

    kenc, kmac = _bac_keys(doc_number, dob, expiry)
    print(f"\nKenc={kenc.hex()}, Kmac={kmac.hex()}")

    print("\nĐọc CCCD via nfcpy USB reader...")
    cache = run_nfcpy(doc_number, dob, expiry)

    # Try to extract MRZ from DG1 to verify
    dg1 = cache.get('0101', b'')
    if dg1:
        d, b_, e = extract_mrz_from_dg1(dg1)
        if d:
            print(f"\nMRZ từ DG1: doc={d} dob={b_} exp={e}")
            if d.rstrip('<') != doc_number.rstrip('<'):
                print(f"WARNING: doc number mismatch! Provided={doc_number} DG1={d}")
        # Auto-update MRZ from DG1 if extraction succeeded
        if d and b_ and e:
            doc_number, dob, expiry = d, b_, e

    save(doc_number, dob, expiry, cache)

if __name__ == '__main__':
    main()
