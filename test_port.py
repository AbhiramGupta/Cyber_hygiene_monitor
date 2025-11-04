# test_server.py
import socket

TEST_PORT = 6000
HOST = "0.0.0.0"   # <- bind to all interfaces so the app treats it as externally reachable

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    s.bind((HOST, TEST_PORT))
    s.listen(1)
    print(f"Test port {TEST_PORT} is now open on {HOST}. Press Enter to close it...")
    input()
except OSError as e:
    print(f"Could not open port {TEST_PORT}: {e}")
finally:
    s.close()
    print(f"Port {TEST_PORT} is now closed.")
