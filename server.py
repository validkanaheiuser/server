#!/usr/bin/env python3
import os
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

import argparse
import socket
import socketserver
import ssl
import struct
import datetime
import sys
import threading
import json
import queue
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

HOST = "0.0.0.0"
PORT = 5566
DASHBOARD_PORT = 5567

# ─── Dashboard state (imported after path is set) ─────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server_state import state as _dstate

# Dashboard HTML is served from dashboard.html next to server.py
_DASHBOARD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')


# ─── Plugin handler ───────────────────────────────────────────────────────────

class PluginHandler:
    def __init__(self, plugins):
        self.plugin_list = []
        for modname in plugins:
            self.plugin_list.append((modname, __import__("plugins.mod_%s" % modname, fromlist=["plugins"])))
            print("Loaded", "mod_%s" % modname)

    def filter(self, client, data):
        for modname, plugin in self.plugin_list:
            if type(data) == list:
                first = data[0]
            else:
                first = data
            first = plugin.handle_data(lambda *x: client.log(*x, tag=modname), first, client.state, client)
            if first is None:
                return None
            if type(data) == list:
                data = [first] + data[1:]
            else:
                data = first
        return data


# ─── NFC relay client handler ─────────────────────────────────────────────────

class NFCGateClientHandler(socketserver.StreamRequestHandler):
    def __init__(self, request, client_address, srv):
        super().__init__(request, client_address, srv)

    def log(self, *args, tag="server"):
        self.server.log(*args, origin=self.client_address, tag=tag)

    def setup(self):
        super().setup()
        self.session = None
        self.state = {}
        self.request.settimeout(300)
        # Disable Nagle algorithm so each APDU is forwarded immediately
        # instead of waiting for ACK of previous segment.
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.log("server", "connected")
        _dstate.client_connected(self.client_address)

    def handle(self):
        super().handle()
        while True:
            try:
                msg_len_data = self.rfile.read(5)
            except socket.timeout:
                self.log("server", "Timeout")
                break
            if len(msg_len_data) < 5:
                break

            msg_len, session = struct.unpack("!IB", msg_len_data)
            data = self.rfile.read(msg_len)
            self.log("server", "data:", bytes(data))

            if msg_len == 0 or session == 0 and self.session is None:
                break

            if self.session != session:
                self.server.remove_client(self, self.session)
                self.session = session
                self.server.add_client(self, session)

            filtered = self.server.plugins.filter(self, data)
            if filtered is not None:
                self.server.send_to_clients(self.session, filtered, self)

    def finish(self):
        super().finish()
        self.server.remove_client(self, self.session)
        self.log("server", "disconnected")
        _dstate.client_disconnected(self.client_address)


# ─── NFC relay server ─────────────────────────────────────────────────────────

class NFCGateServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, request_handler, plugins, tls_options=None, bind_and_activate=True):
        self.allow_reuse_address = True
        super().__init__(server_address, request_handler, bind_and_activate)
        self.clients = {}
        self.plugins = PluginHandler(plugins)
        self.tls_options = tls_options
        self.log("NFCGate server listening on", server_address)
        if self.tls_options:
            self.log("TLS enabled with cert {} and key {}".format(
                self.tls_options["cert_file"], self.tls_options["key_file"]))

    def get_request(self):
        client_socket, from_addr = super().get_request()
        if not self.tls_options:
            return client_socket, from_addr
        return self.tls_options["context"].wrap_socket(client_socket, server_side=True), from_addr

    def log(self, *args, origin="0", tag="server"):
        print(datetime.datetime.now(), "["+tag+"]", origin, *args)

    def add_client(self, client, session):
        if session is None:
            return
        if session not in self.clients:
            self.clients[session] = []
        ip = client.client_address[0]
        stale = [c for c in self.clients[session] if c.client_address[0] == ip]
        for old in stale:
            self.log("Kicking stale connection from", ip, "in session", session, tag="server")
            try: old.request.close()
            except Exception: pass
            self.clients[session].remove(old)
        self.clients[session].append(client)
        client.log("joined session", session)
        _dstate.client_joined_session(client.client_address, session)

    def remove_client(self, client, session):
        if session is None or session not in self.clients:
            return
        try:
            self.clients[session].remove(client)
        except ValueError:
            pass
        client.log("left session", session)

    def send_to_clients(self, session, msgs, origin):
        if session is None or session not in self.clients:
            return
        if type(msgs) != list:
            msgs = [msgs]
        for client in self.clients[session]:
            if client is origin:
                continue
            for msg in msgs:
                # Pack length header + payload in one write() → one sendall() →
                # single TCP segment.  Avoids Nagle stalling the 4-byte header
                # while waiting for the next write to fill the segment.
                client.wfile.write(int.to_bytes(len(msg), 4, byteorder='big') + msg)


# ─── HTTP dashboard server ────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress access log noise

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path in ('', '/'):
            self._serve_dashboard()
        elif path == '/api/status':
            self._json(200, _dstate.snapshot())
        elif path == '/events':
            self._serve_sse()
        else:
            self._json(404, {'error': 'Không tìm thấy'})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            body = {}

        if path == '/api/mrz':
            doc  = str(body.get('doc_number', '')).strip()
            dob  = str(body.get('dob', '')).strip()
            exp  = str(body.get('expiry', '')).strip()
            if not doc or not dob or not exp:
                self._json(400, {'error': 'Thiếu thông tin MRZ (doc_number / dob / expiry)'})
                return
            ip = self.client_address[0]
            _dstate.store_mrz(ip, doc, dob, exp)
            print(datetime.datetime.now(), "[dashboard] MRZ nhận từ", ip,
                  f"doc={doc[:4]}****  dob={dob}  expiry={exp}")
            self._json(200, {'status': 'ok', 'message': f'MRZ đã lưu — {doc[:4]}****'})

        elif path == '/api/cccd/delete':
            doc = str(body.get('doc_number', '')).strip()
            _dstate.delete_cccd(doc)
            self._json(200, {'status': 'ok'})

        elif path == '/api/mode':
            mode = str(body.get('mode', 'train')).strip()
            try:
                import sys as _sys
                key = 'plugins.mod_cccd_cache'
                if key in _sys.modules:
                    _sys.modules[key].MODE = mode
                cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cccd_config.json')
                with open(cfg_path) as f:
                    cfg = json.load(f)
                cfg['mode'] = mode
                with open(cfg_path, 'w') as f:
                    json.dump(cfg, f, indent=2)
                self._json(200, {'status': 'ok', 'mode': mode})
            except Exception as e:
                self._json(500, {'error': str(e)})

        else:
            self._json(404, {'error': 'Không tìm thấy'})

    def _serve_dashboard(self):
        try:
            with open(_DASHBOARD_PATH, 'rb') as f:
                html = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(html))
            self._cors()
            self.end_headers()
            self.wfile.write(html)
        except FileNotFoundError:
            self._json(404, {'error': 'dashboard.html không tìm thấy'})

    def _serve_sse(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self._cors()
        self.end_headers()
        q = queue.Queue(maxsize=200)
        _dstate.add_sse_client(q)
        try:
            while True:
                try:
                    msg = q.get(timeout=20)
                    self.wfile.write(msg.encode('utf-8'))
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b': keepalive\n\n')
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            _dstate.remove_sse_client(q)

    def _json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self._cors()
        self.end_headers()
        self.wfile.write(body)


class ThreadingDashboardServer(HTTPServer):
    """Threaded HTTP server so SSE connections don't block the event loop."""
    def process_request(self, request, client_address):
        t = threading.Thread(target=self._handle, args=(request, client_address))
        t.daemon = True
        t.start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


# ─── Argument parsing & main ─────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(prog="NFCGate server")
    parser.add_argument("plugins", type=str, nargs="*", help="Plugin modules to load.")
    parser.add_argument("-s", "--tls", help="Enable TLS.", default=False, action="store_true")
    parser.add_argument("--tls_cert", help="TLS certificate PEM.", action="store")
    parser.add_argument("--tls_key",  help="TLS key PEM.",         action="store")
    parser.add_argument("--no-dashboard", help="Disable HTTP dashboard.", action="store_true")
    args = parser.parse_args()
    tls_options = None
    if args.tls:
        if args.tls_cert is None or args.tls_key is None:
            print("Cần chỉ định tls_cert và tls_key!")
            sys.exit(1)
        tls_options = {"cert_file": args.tls_cert, "key_file": args.tls_key}
        try:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(tls_options["cert_file"], tls_options["key_file"])
            tls_options["context"] = ctx
        except ssl.SSLError:
            print("Không thể tải certificate. Kiểm tra định dạng và quyền file!")
            sys.exit(1)
    return args.plugins, tls_options, not args.no_dashboard


def main():
    plugins, tls_options, run_dashboard = parse_args()

    # Set cache path in state
    _dstate.cache_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'cccd_cache.json')

    # Start HTTP dashboard in background thread
    if run_dashboard:
        dash = ThreadingDashboardServer(('0.0.0.0', DASHBOARD_PORT), DashboardHandler)
        t = threading.Thread(target=dash.serve_forever, name='dashboard-http')
        t.daemon = True
        t.start()
        print(datetime.datetime.now(),
              f"[dashboard] Bảng điều khiển: http://localhost:{DASHBOARD_PORT}")

    NFCGateServer((HOST, PORT), NFCGateClientHandler, plugins, tls_options).serve_forever()


if __name__ == "__main__":
    main()
