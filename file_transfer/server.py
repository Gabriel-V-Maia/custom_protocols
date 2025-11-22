import struct
import socket
import json 


HOST = "127.0.0.1"
PORT = 6000

class PacketParser:

    @staticmethod
    def read_exact(sock, n: int):
        buffer = b""

        while (len(buffer) < n):
            chunk = sock.recv(n - len(buffer))

            if not chunk:
                raise ConnectionError("conexão abortada")

            buffer += chunk

        return buffer

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        try:
            while True:
                header_len_bytes = PacketParser.read_exact(conn, 4)
                header_len = struct.unpack(">I", header_len_bytes)[0]

                header_bytes = PacketParser.read_exact(conn, header_len)
                header = json.loads(header_bytes.decode())
                print("Header:", header)

                nonce = PacketParser.read_exact(conn, 12)
                print("Nonce:", nonce.hex())

                payload_len_bytes = PacketParser.read_exact(conn, 4)
                payload_len = struct.unpack(">I", payload_len_bytes)[0]
                print("Payload length:", payload_len)

                payload = PacketParser.read_exact(conn, payload_len)
                print("Payload received:", len(payload), "bytes")

        except ConnectionError:
            print("conexão fechada")
        except Exception as e:
            print(f"{e}")

