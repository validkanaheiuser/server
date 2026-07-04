"""
server_state.py — Shared relay state for the NFCGate dashboard.
Singleton imported by server.py (HTTP layer) and plugins/mod_dashboard.py (APDU logging).
"""
import threading
import datetime
import os
import json
import queue
from collections import deque

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now():    return datetime.datetime.now().strftime('%H:%M:%S')
def _nowms():  return datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
def _nowfull():return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


# ─── APDU decoder ─────────────────────────────────────────────────────────────

def decode_apdu(apdu: bytes, is_cmd: bool) -> tuple:
    """Return (category, description) for an APDU byte string."""
    if not apdu:
        return ('default', '?')

    # ── Response ──────────────────────────────────────────────────────────────
    if not is_cmd:
        if len(apdu) == 2:
            sw = (apdu[0] << 8) | apdu[1]
            SW = {
                0x9000: ('ok',      '✓ OK'),
                0x6982: ('error',   '✗ Không đủ quyền bảo mật'),
                0x6983: ('error',   '✗ Đã khóa xác thực'),
                0x6985: ('error',   '✗ Điều kiện không thỏa mãn'),
                0x6988: ('error',   '✗ Lỗi MAC bảo mật (6988)'),
                0x6A82: ('error',   '✗ Không tìm thấy tệp (6A82)'),
                0x6A86: ('error',   '✗ P1-P2 sai'),
                0x6B00: ('error',   '✗ Offset sai (6B00)'),
                0x6C00: ('error',   '✗ Le sai (6C00)'),
                0x6D00: ('error',   '✗ Lệnh không được hỗ trợ (6D00)'),
                0x6E00: ('error',   '✗ CLA không hỗ trợ'),
                0x6900: ('error',   '✗ Lệnh không được phép'),
                0x6300: ('warning', '⚠ Xác thực thất bại'),
            }
            if sw in SW:
                return SW[sw]
            if (sw >> 8) == 0x61:
                return ('ok', f'✓ Còn {sw & 0xFF} byte')
            if (sw >> 8) == 0x62:
                return ('warning', f'⚠ SW {sw:04X} (cảnh báo)')
            return ('default', f'SW {sw:04X}')

        # PACE response (7C outer TLV)
        if apdu[0] == 0x7C and len(apdu) >= 3:
            inner = apdu[2] if len(apdu) > 2 else 0
            PACE_R = {
                0x80: 'PACE: Nonce mã hóa (bước 1)',
                0x82: 'PACE: Ánh xạ nonce từ chip (bước 2)',
                0x84: 'PACE: Khóa công khai chip (bước 3)',
                0x86: 'PACE: Token xác thực chip (bước 4)',
            }
            sw = f'{apdu[-2]:02X}{apdu[-1]:02X}' if len(apdu) >= 2 else '????'
            return ('pace', f'{PACE_R.get(inner, "PACE phản hồi")}  SW={sw}')

        # SM response (DO'87' DO'99' DO'8E')
        if len(apdu) > 4 and apdu[0] in (0x87, 0x99, 0x77):
            sw_str = ''
            i = 0
            while i < len(apdu) - 1:
                tag = apdu[i]; i += 1
                if i >= len(apdu): break
                ln = apdu[i]; i += 1
                if ln == 0x81 and i < len(apdu): ln = apdu[i]; i += 1
                elif ln == 0x82 and i + 1 < len(apdu):
                    ln = (apdu[i] << 8) | apdu[i+1]; i += 2
                if tag == 0x99 and ln >= 2 and i + 1 < len(apdu):
                    sw = (apdu[i] << 8) | apdu[i+1]
                    sw_str = f'✓ OK' if sw == 0x9000 else f'SW={sw:04X}'
                i += ln
            return ('sm', f'SM Response  {sw_str}')

        # BAC GET CHALLENGE response (8-byte nonce + 9000)
        if len(apdu) == 10 and apdu[-2:] == b'\x90\x00':
            return ('read', f'GET CHALLENGE response  nonce={apdu[:8].hex().upper()}')

        sw = f'{apdu[-2]:02X}{apdu[-1]:02X}' if len(apdu) >= 2 else '????'
        return ('default', f'Response {len(apdu)-2}B  SW={sw}')

    # ── Command ───────────────────────────────────────────────────────────────
    if len(apdu) < 2:
        return ('default', '?')
    cla, ins = apdu[0], apdu[1]
    p1 = apdu[2] if len(apdu) > 2 else 0
    p2 = apdu[3] if len(apdu) > 3 else 0

    if cla == 0x00:
        if ins == 0xA4:
            lc = apdu[4] if len(apdu) > 4 else 0
            d = apdu[5:5+lc] if len(apdu) >= 5+lc else b''
            if p1 == 0x04:
                KNOWN = {
                    bytes.fromhex('A0000002471001'): 'CCCD AID',
                    bytes.fromhex('D2760000850101'): 'AID phụ (D276...)',
                }
                return ('select', f'SELECT  {KNOWN.get(d, d.hex().upper())}')
            fid = d.hex().upper()
            FID_NAME = {'011E': 'EF.COM', '011D': 'EF.SOD', '0101': 'EF.DG1',
                        '0102': 'EF.DG2 (ảnh)', '010E': 'EF.DG14 (CA params)'}
            return ('select', f'SELECT FID {FID_NAME.get(fid, fid)}')
        if ins == 0x84: return ('read',   'GET CHALLENGE — BAC bước 1')
        if ins == 0x82: return ('default','EXTERNAL AUTHENTICATE — BAC bước 2')
        if ins == 0x22: return ('pace',   'MSE:SET AT — Khởi tạo PACE')
        if ins == 0x86: return ('pace',   'PACE: Xác thực lẫn nhau — bước 4 (CLA=00)')
        if ins == 0xB0:
            off = ((p1 & 0x7F) << 8) | p2
            le = apdu[4] if len(apdu) > 4 else 0
            return ('read', f'READ BINARY  @{off:04X}  Le={le}')
        return ('default', f'CLA=00 INS={ins:02X} P1={p1:02X} P2={p2:02X}')

    if cla == 0x10 and ins == 0x86:
        lc = apdu[4] if len(apdu) > 4 else 0
        body = apdu[5:5+lc]
        if len(body) >= 2 and body[0] == 0x7C:
            inner = body[2:] if len(body) > 2 else b''
            t = inner[0] if inner else 0xFF
            STEPS = {0x80: 'GET NONCE — bước 1', 0x81: 'Ánh xạ nonce — bước 2',
                     0x83: 'Thỏa thuận khóa — bước 3'}
            return ('pace', f'PACE: {STEPS.get(t, "bước ?")}  (CLA=10, chained)')
        return ('pace', 'PACE STEP (chained)')

    if cla == 0x0C:
        if ins == 0xA4:
            return ('sm', f'SM SELECT  {"AID" if p1==4 else "FID"}')
        if ins == 0xB0:
            off = ((p1 & 0x7F) << 8) | p2
            do97 = b''
            if len(apdu) > 5:
                body = apdu[5:5 + apdu[4]]
                i = 0
                while i < len(body) - 1:
                    t = body[i]; i += 1
                    if i >= len(body): break
                    ln = body[i]; i += 1
                    if t == 0x97 and ln > 0: do97 = body[i:i+ln]
                    i += ln
            le = int.from_bytes(do97, 'big') if do97 else 0
            return ('sm', f'SM READ BINARY  @{off:04X}  Le={le}')
        if ins == 0x86: return ('sm', 'SM GENERAL AUTHENTICATE')
        return ('sm', f'SM INS={ins:02X}')

    return ('default', f'CLA={cla:02X} INS={ins:02X} P1={p1:02X} P2={p2:02X}')


# ─── State singleton ──────────────────────────────────────────────────────────

class RelayState:
    """Thread-safe live state consumed by the HTTP dashboard."""

    def __init__(self):
        self._lock = threading.Lock()
        self.clients  = {}      # (ip, port) → dict
        self.sessions = {}      # session_id → dict
        self.apdu_log = deque(maxlen=500)
        self.mrz_by_ip = {}    # ip → {doc_number, dob, expiry, received_at}
        self.cccd_list = {}    # doc_number → info dict
        self.cache_path = ''   # set by server at startup
        self._sse_queues = []  # list of queue.Queue for SSE clients

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def client_connected(self, addr):
        with self._lock:
            self.clients[addr] = {
                'ip': addr[0], 'port': addr[1],
                'role': 'unknown', 'session': None,
                'connected_at': _now(), 'apdu_count': 0,
            }

    def client_disconnected(self, addr):
        with self._lock:
            self.clients.pop(addr, None)
            addr_str = f'{addr[0]}:{addr[1]}'
            for sid, s in list(self.sessions.items()):
                devs = s.get('devices', [])
                if addr_str in devs:
                    devs.remove(addr_str)
                if not devs:
                    del self.sessions[sid]

    def client_joined_session(self, addr, session_id):
        with self._lock:
            if addr in self.clients:
                self.clients[addr]['session'] = session_id
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    'devices': [], 'reader': None, 'hce': None,
                    'start_time': _now(), 'apdu_count': 0,
                    'cccd': None, 'pace_done': False, 'bac_done': False,
                    'current_file': None,
                }
            addr_str = f'{addr[0]}:{addr[1]}'
            if addr_str not in self.sessions[session_id]['devices']:
                self.sessions[session_id]['devices'].append(addr_str)

    # ── APDU logging ──────────────────────────────────────────────────────────

    def log_apdu(self, addr, session_id, is_card: bool, apdu_bytes: bytes):
        cat, desc = decode_apdu(apdu_bytes, is_card)

        with self._lock:
            if addr in self.clients:
                if self.clients[addr]['role'] == 'unknown':
                    self.clients[addr]['role'] = 'hce' if is_card else 'reader'
                self.clients[addr]['apdu_count'] += 1

            s = self.sessions.get(session_id)
            if s:
                s['apdu_count'] += 1
                addr_str = f'{addr[0]}:{addr[1]}'
                if is_card  and not s['hce']:    s['hce']    = addr_str
                if not is_card and not s['reader']: s['reader'] = addr_str
                if s['cccd'] is None and addr[0] in self.mrz_by_ip:
                    s['cccd'] = self.mrz_by_ip[addr[0]]
                # Update session phase flags
                if cat == 'pace' and 'bước 4' in desc:
                    s['pace_done'] = True
                if 'BAC bước 2' in desc:
                    s['bac_done'] = True
                if 'SM SELECT' in desc or 'SELECT FID' in desc:
                    s['current_file'] = desc.split()[-1] if desc else None

            entry = {
                'ts': _nowms(),
                'session': session_id,
                'dir': '→ Chip' if is_card else '← Chip',
                'is_card': is_card,
                'cat': cat,
                'apdu': apdu_bytes[:40].hex().upper() + ('…' if len(apdu_bytes) > 40 else ''),
                'desc': desc,
                'len': len(apdu_bytes),
            }
            self.apdu_log.appendleft(entry)

        # Push to SSE clients (outside lock to avoid deadlock)
        self._push_sse('apdu', entry)

    # ── MRZ / CCCD management ─────────────────────────────────────────────────

    def store_mrz(self, ip: str, doc_number: str, dob: str, expiry: str):
        with self._lock:
            self.mrz_by_ip[ip] = {
                'doc_number': doc_number, 'dob': dob,
                'expiry': expiry, 'received_at': _now(),
            }
            if doc_number not in self.cccd_list:
                self.cccd_list[doc_number] = {
                    'doc_number': doc_number, 'dob': dob, 'expiry': expiry,
                    'enrolled_at': _nowfull(), 'last_used': None,
                    'files': [], 'trained': False,
                }
        # Also refresh config file
        _write_config(doc_number, dob, expiry)
        # Update live module globals if cccd_cache is loaded
        _patch_cccd_cache(doc_number, dob, expiry)

    def mark_files_cached(self, files: list):
        with self._lock:
            # Associate with the last-enrolled doc_number
            if not self.cccd_list:
                return
            last = list(self.cccd_list.values())[-1]
            last['trained'] = True
            last['files'] = files
            last['last_used'] = _nowfull()

    def delete_cccd(self, doc_number: str):
        with self._lock:
            self.cccd_list.pop(doc_number, None)

    # ── SSE helpers ───────────────────────────────────────────────────────────

    def add_sse_client(self, q):
        with self._lock:
            self._sse_queues.append(q)

    def remove_sse_client(self, q):
        with self._lock:
            try: self._sse_queues.remove(q)
            except ValueError: pass

    def _push_sse(self, event: str, data: dict):
        msg = f'event: {event}\ndata: {json.dumps(data, default=str, ensure_ascii=False)}\n\n'
        dead = []
        for q in self._sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            self.remove_sse_client(q)

    # ── Snapshot for HTTP polling ─────────────────────────────────────────────

    def _cache_files(self) -> dict:
        if not self.cache_path or not os.path.exists(self.cache_path):
            return {}
        try:
            with open(self.cache_path) as f:
                raw = json.load(f)
            return {_FID_NAME.get(k, k): len(v) // 2 for k, v in raw.items()}
        except Exception:
            return {}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'ts': _now(),
                'clients':  {f'{a[0]}:{a[1]}': {**v} for a, v in self.clients.items()},
                'sessions': dict(self.sessions),
                'apdu_log': list(self.apdu_log)[:100],
                'cccd_list': dict(self.cccd_list),
                'cache_files': self._cache_files(),
            }


# ─── Config helpers ───────────────────────────────────────────────────────────

_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_SERVER_DIR, 'cccd_config.json')


def _write_config(doc_number: str, dob: str, expiry: str):
    cfg = {
        '_comment': 'mode: train = ghi từ chip thật | serve = trả từ cache',
        'mode': 'train', 'doc_number': doc_number,
        'dob': dob, 'expiry': expiry,
    }
    try:
        with open(_CONFIG_PATH, 'w') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _patch_cccd_cache(doc_number: str, dob: str, expiry: str):
    try:
        import sys
        key = 'plugins.mod_cccd_cache'
        if key in sys.modules:
            m = sys.modules[key]
            m.DOC_NUMBER = doc_number
            m.DOB = dob
            m.EXPIRY = expiry
    except Exception:
        pass


# ─── FID → human-readable name (used by _cache_files and mod_cccd_cache) ─────
_FID_NAME = {
    '011E': 'COM',
    '011D': 'SOD',
    '0101': 'DG1',
    '0102': 'DG2',
    '010E': 'DG14',
}

# ─── Singleton ────────────────────────────────────────────────────────────────
state = RelayState()
