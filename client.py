import blake3
import socket
import json
import os
import zlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------
#  Utilidades de criptografia
# ---------------------------------------------------------

def encrypt_blob(header: bytes, payload: bytes, key: bytes):
    """
    Criptografa (header + payload) usando AES-GCM.
    header entra como AAD (autenticado) sem ir para dentro do ciphertext.
    payload é comprimido e criptografado.
    """
    aes = AESGCM(key)

    nonce = os.urandom(12)        # Nonce padrão AES-GCM
    compressed = zlib.compress(payload, 9)

    # Criptografa o payload, autenticando os headers
    encrypted = aes.encrypt(nonce, compressed, header)

    return nonce, encrypted


# ---------------------------------------------------------
# Packet
# ---------------------------------------------------------

@dataclass
class Packet:
    header: dict
    nonce: bytes
    encrypted_payload: bytes

    def to_bytes(self) -> bytes:
        header_json = json.dumps(self.header).encode("utf-8")

        header_len = len(header_json).to_bytes(4, "big")
        payload_len = len(self.encrypted_payload).to_bytes(4, "big")

        # Formato final:
        # [4 bytes header_len][header_json]
        # [12 bytes nonce]
        # [4 bytes payload_len][encrypted_payload]
        return (
            header_len
            + header_json
            + self.nonce
            + payload_len
            + self.encrypted_payload
        )

    @staticmethod
    def from_file(user: str, source: str, path: str, key: bytes):
        with open(path, "rb") as f:
            payload = f.read()

        checksum = blake3.blake3(payload).hexdigest()
        size = len(payload)
        name = os.path.basename(path)

        # Headers em plaintext, mas autenticados via AAD
        header = {
            "user": user,
            "source": source,
            "name": name,
            "size": size,
            "checksum": checksum
        }

        header_json = json.dumps(header).encode("utf-8")

        nonce, encrypted = encrypt_blob(
            header=header_json,
            payload=payload,
            key=key
        )

        return Packet(
            header=header,
            nonce=nonce,
            encrypted_payload=encrypted
        )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():
    # Chave fixa usada pelo cliente e pelo servidor
    KEY = AESGCM.generate_key(256)  # AES‑256

    packet = Packet.from_file(
        user="a",
        source="192.168.0.1",
        path="test.txt",
        key=KEY
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 6000))
        s.sendall(packet.to_bytes())


if __name__ == "__main__":
    main()


