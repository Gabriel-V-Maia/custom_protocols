import struct
import socket
import json
import zlib
import blake3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 6000

AES_KEY = (
    b"\x7a\x0c\x4e\xb1\x19\x83\x5d\xfa"
    b"\x3c\x52\x8f\x91\xde\x24\x6b\x07"
    b"\xa8\xbb\x41\x9f\x02\x66\xcd\x73"
    b"\xf4\x8d\x20\xea\x5a\x1c\xb9\x0f"
)

def decrypt_uncompress(payload: bytes, nonce: bytes, header: bytes) -> bytes:
    aes = AESGCM(AES_KEY)
    compressed = aes.decrypt(nonce, payload, header)
    return zlib.decompress(compressed)

def check_checksum(checksum, received):
    received_file_checksum = blake3.blake3(received).hexdigest()
    print("Checksum ok:", checksum == received_file_checksum)

class PacketParser:

    @staticmethod
    def read_exact(sock, n: int):
        buffer = b""
        while len(buffer) < n:
            chunk = sock.recv(n - len(buffer))
            if not chunk:
                raise ConnectionError("conexão abortada")
            buffer += chunk
        return buffer

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Aguardando conexão...")
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

                payload = PacketParser.read_exact(conn, payload_len)
                print(f"Payload received: {len(payload)} bytes")

                payload_decrypted = decrypt_uncompress(payload, nonce, header_bytes)
                
                check_checksum(header["checksum"], payload_decrypted)

                print("---")
        except ConnectionError:
            print("conexão fechada")
        except Exception as e:
            print(f"Erro: {e}")


