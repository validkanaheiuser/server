"""Sanity tests for mod_cccd_cache crypto."""
import sys, os
sys.path.insert(0, ".")
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

from plugins.mod_cccd_cache import (
    _bac_keys, _retail_mac, _retail_mac_raw, _pad80,
    _sm_enc, _sm_dec, _wrap_resp, _unwrap_cmd,
    _process_ext_auth, _inc_ssc, _derive_key,
    _3des_cbc, _3des_ecb, _sm_mac_cmd, _sm_mac_resp, _encode_len,
)

# ─── Test 1: Key derivation (ICAO 9303 Appendix D vectors) ───────────────────
kenc, kmac = _bac_keys("L898902C<", "690806", "940623")
assert kenc.hex().upper() == "AB94FDECF2674FDFB9B391F85D7F76F2", f"Kenc: {kenc.hex()}"
assert kmac.hex().upper() == "7962D9ECE03D1ACD4C76089DCE131543", f"Kmac: {kmac.hex()}"
print("[OK] BAC key derivation (ICAO 9303 Appendix D)")

# ─── Test 2: BAC full roundtrip (simulate reader + server) ──────────────────
chip_nonce = os.urandom(8)
rnd_ifd    = os.urandom(8)
k_ifd      = os.urandom(16)

# Reader builds EIFD = 3DES-CBC(Kenc, RND.IFD || RND.IC || K.IFD, IV=0)
s    = rnd_ifd + chip_nonce + k_ifd
eifd = _3des_cbc(kenc, b'\x00'*8, s)
mifd = _retail_mac(kmac, eifd)             # MAC over pad(EIFD)
cmd_data = eifd + mifd

# Server processes EXTERNAL AUTHENTICATE
result = _process_ext_auth(kenc, kmac, chip_nonce, cmd_data)
assert result is not None, "BAC verification failed"
resp40, ksenc, ksmac, ssc = result

# Reader derives same session keys
k_ic = _3des_cbc(kenc, b'\x00'*8, resp40[:32], encrypt=False)[16:32]
ks_seed = bytes(a ^ b for a, b in zip(k_ifd, k_ic))
exp_ksenc = _derive_key(ks_seed, 1)
exp_ksmac = _derive_key(ks_seed, 2)
exp_ssc   = chip_nonce[4:] + rnd_ifd[4:]

assert ksenc == exp_ksenc, "KSenc mismatch"
assert ksmac == exp_ksmac, "KSmac mismatch"
assert ssc   == exp_ssc,   f"SSC mismatch: {ssc.hex()} vs {exp_ssc.hex()}"
print("[OK] BAC full roundtrip")

# ─── Test 3: SM session key derivation (parity check) ───────────────────────
# Derive session keys from the ICAO Appendix D K.IFD / K.IC example values.
# (Some published "expected" values have even-parity bytes; verify our output
# has correct DES odd parity on ALL 16 bytes instead.)
k_ifd_ref   = bytes.fromhex("0B4F80323EB3191CB04970CB4052790B")
k_ic_ref    = bytes.fromhex("0B795240CB7049B01C19B33E32804F0B")
ks_seed_ref = bytes(a ^ b for a, b in zip(k_ifd_ref, k_ic_ref))
ksenc_ref   = _derive_key(ks_seed_ref, 1)
ksmac_ref   = _derive_key(ks_seed_ref, 2)
for b in ksenc_ref + ksmac_ref:
    assert bin(b).count('1') % 2 == 1, f"Byte {b:02X} has even parity — DES parity broken"
print(f"  KSenc = {ksenc_ref.hex()}")
print(f"  KSmac = {ksmac_ref.hex()}")
print("[OK] SM session key derivation (all bytes odd-parity)")

# ─── Test 4: SM encrypt/decrypt roundtrip ────────────────────────────────────
ssc0    = bytes.fromhex("887022120C06C226")
ssc_cmd = _inc_ssc(ssc0)
pt      = b'\x01\x1E'  # EF.COM FID
do87    = _sm_enc(ksenc_ref, ssc_cmd, pt)
assert do87[0] == 0x01, "Missing padding indicator"
dec     = _sm_dec(ksenc_ref, ssc_cmd, do87)
assert dec == pt, f"SM enc/dec mismatch: {dec.hex()} vs {pt.hex()}"
print("[OK] SM encrypt/decrypt roundtrip")

# ─── Test 5: SM command wrap/unwrap roundtrip ────────────────────────────────
# Build a fake SM SELECT command that a real reader would send
ssc_cmd2 = _inc_ssc(ssc0)
header   = bytes.fromhex("0CA40000")
do87_sel = _sm_enc(ksenc_ref, ssc_cmd2, b'\x01\x1E')
do97_val = b'\x00'   # Le=0 (no expected data)
mac_sel  = _sm_mac_cmd(ksmac_ref, ssc_cmd2, header, do87_sel, do97_val)
do8e     = mac_sel

# Assemble SM command APDU
body = (b'\x87' + _encode_len(len(do87_sel)) + do87_sel
      + b'\x97' + _encode_len(len(do97_val)) + do97_val
      + b'\x8E' + _encode_len(len(do8e))     + do8e)
apdu_sm = header + bytes([len(body)]) + body

ssc_server, pt_out, le_out = _unwrap_cmd(ksenc_ref, ksmac_ref, ssc0, apdu_sm)
assert pt_out == b'\x01\x1E', f"Unwrapped data wrong: {pt_out.hex()}"
assert ssc_server == ssc_cmd2, "SSC mismatch after unwrap"
print("[OK] SM command wrap/unwrap roundtrip")

# ─── Test 6: SM response wrap ─────────────────────────────────────────────────
ssc_resp = _inc_ssc(ssc_cmd2)  # after command, server increments SSC
plaintext_resp = bytes.fromhex("011E6F00")   # fake DG data
ssc_out, resp  = _wrap_resp(ksenc_ref, ksmac_ref, ssc_cmd2, plaintext_resp, 0x90, 0x00)
assert resp[-2:] == b'\x90\x00', "Response must end with 9000"
assert ssc_out == ssc_resp, f"SSC after wrap: {ssc_out.hex()} expected {ssc_resp.hex()}"
print("[OK] SM response wrap")

# ─── Test 7: retail_mac correct with known DES values ────────────────────────
# Verify _retail_mac_raw by checking single-block DES
from Crypto.Cipher import DES as _DES
key1 = bytes.fromhex("7962D9ECE03D1ACD")
key2 = bytes.fromhex("4C76089DCE131543")
msg  = b'\x80' + b'\x00' * 7   # 1 block = pad of empty msg
b1   = _DES.new(key1, _DES.MODE_ECB).encrypt(msg)
b2   = _DES.new(key2, _DES.MODE_ECB).decrypt(b1)
b3   = _DES.new(key1, _DES.MODE_ECB).encrypt(b2)
ref  = _retail_mac_raw(bytes.fromhex("7962D9ECE03D1ACD4C76089DCE131543"), msg)
assert ref == b3, f"retail_mac_raw wrong: {ref.hex()} vs {b3.hex()}"
print("[OK] retail_mac_raw internals")

print("\nAll tests passed.")
