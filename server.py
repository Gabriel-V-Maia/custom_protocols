
import socket
import struct
import json

HOST = "127.0.0.1"
PORT = 6000

def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão fechada antes de receber tudo")
        buf.extend(chunk)
    return bytes(buf)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

    with conn:
        print(f"Connected by {addr}")

        header_len_bytes = recv_exact(conn, 4)
        header_len = struct.unpack(">I", header_len_bytes)[0]

        header_bytes = recv_exact(conn, header_len)
        header = json.loads(header_bytes.decode())

        print("HEADER:", header)

        payload_len_bytes = recv_exact(conn, 4)
        payload_len = struct.unpack(">I", payload_len_bytes)[0]

        payload = recv_exact(conn, payload_len)

        print("PAYLOAD LEN:", len(payload))
        print("PAYLOAD", payload)


