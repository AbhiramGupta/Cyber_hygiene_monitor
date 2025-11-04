import sys
import os
import socket
import threading
import time
import psutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TEST_PORT = 6001

def _start_listener(stop_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', TEST_PORT))
    s.listen(1)
    try:
        while not stop_event.is_set():
            time.sleep(0.1)
    finally:
        s.close()

def test_port_is_listening():
    stop_event = threading.Event()
    t = threading.Thread(target=_start_listener, args=(stop_event,), daemon=True)
    t.start()
    # give the listener a moment to start
    time.sleep(0.2)

    found = False
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == 'LISTEN' and getattr(conn.laddr, 'port', None) == TEST_PORT:
            found = True
            break

    stop_event.set()
    t.join(timeout=1)
    assert found, f"Port {TEST_PORT} should be listening"
