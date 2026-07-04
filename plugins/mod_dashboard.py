"""
mod_dashboard.py — NFCGate plugin: log every APDU to the live dashboard state.
Add to command: python server.py mod_dashboard cccd_cache log
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from plugins.c2c_pb2 import NFCData
from plugins.c2s_pb2 import ServerData
from server_state import state


def handle_data(log, data, session_state, client=None):
    """Pass-through plugin: decode and log every APDU, never modify data."""
    try:
        srv = ServerData()
        srv.ParseFromString(data)
        if srv.opcode != ServerData.OP_PSH:
            return data

        nfc = NFCData()
        nfc.ParseFromString(srv.data)
        apdu    = bytes(nfc.data)
        is_card = (nfc.data_source == NFCData.CARD)

        addr       = getattr(client, 'client_address', ('0.0.0.0', 0))
        session_id = getattr(client, 'session', None)

        if apdu:
            state.log_apdu(addr, session_id, is_card, apdu)
    except Exception:
        pass  # never disrupt relay

    return data
