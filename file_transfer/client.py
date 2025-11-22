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

def encrypt_blob(header: bytes, payload: bytes, key):
    """
    Criptografa (header + payload) usando AES-GCM.
    header entra como AAD (autenticado) sem ir para dentro do ciphertext.
    payload é comprimido e criptografado.
    """
    aes = AESGCM(key)

    nonce = os.urandom(12)        # Nonce padrão AES-GCM
    compressed = zlib.compress(payload, 9)

    encrypted = aes.encrypt(nonce, compressed, header)

    return nonce, encrypted


# ---------------------------------------------------------
# Header registry
# ---------------------------------------------------------

HEADER_TEMPLATES = {}

def register_header(name, fields):
    """
    Registra um template de header.
    name: nome do template
    fields: lista de strings (nomes dos campos)
    """
    HEADER_TEMPLATES[name] = fields

def build_header(template_name, payload=None, **kwargs):
    """
    Cria um dict de header a partir do template.
    Calcula automaticamente size e checksum se existirem.
    """
    if template_name not in HEADER_TEMPLATES:
        raise ValueError(f"Template {template_name} não registrado")
    
    header = {field: kwargs[field] for field in HEADER_TEMPLATES[template_name] if field in kwargs}

    if payload is not None:
        if "size" in HEADER_TEMPLATES[template_name]:
            header["size"] = len(payload)
        if "checksum" in HEADER_TEMPLATES[template_name]:
            header["checksum"] = blake3.blake3(payload).hexdigest()

    return header


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

        header = build_header(
            "file",
            user=user,
            source=source,
            name=os.path.basename(path),
            payload=payload
        )

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
# Registro de header padrão
# ---------------------------------------------------------

register_header("file", ["user", "source", "name", "size", "checksum"])


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    AES_KEY = (
        b"\x7a\x0c\x4e\xb1\x19\x83\x5d\xfa"
        b"\x3c\x52\x8f\x91\xde\x24\x6b\x07"
        b"\xa8\xbb\x41\x9f\x02\x66\xcd\x73"
        b"\xf4\x8d\x20\xea\x5a\x1c\xb9\x0f"
    )

    packet_file1 = Packet.from_file(
        user="a",
        source="192.168.0.1",
        path="test.txt",
        key=AES_KEY
    )

    packet_file2 = Packet.from_file(
        user="b",
        source="192.168.0.2",
        path="test.txt",
        key=AES_KEY
    )

    payload_msg1 = b"Hello, this is a test message"
    header_msg1 = build_header(
        "message",
        user="alice",
        source="10.0.0.5",
        text=payload_msg1.decode(),
        payload=payload_msg1
    )
    nonce_msg1, encrypted_msg1 = encrypt_blob(
        json.dumps(header_msg1).encode(),
        payload_msg1,
        AES_KEY
    )
    packet_msg1 = Packet(header_msg1, nonce_msg1, encrypted_msg1)

    payload_msg2 = b"Second message for testing"
    header_msg2 = build_header(
        "message",
        user="bob",
        source="10.0.0.6",
        text=payload_msg2.decode(),
        payload=payload_msg2
    )
    nonce_msg2, encrypted_msg2 = encrypt_blob(
        json.dumps(header_msg2).encode(),
        payload_msg2,
        AES_KEY
    )
    packet_msg2 = Packet(header_msg2, nonce_msg2, encrypted_msg2)

    packets = [packet_file1, packet_file2, packet_msg1, packet_msg2]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 6000))
        for p in packets:
            s.sendall(p.to_bytes())
            print(f"Enviado pacote: {p.header}")


if __name__ == "__main__":
    register_header("message", ["user", "source", "text", "checksum"])
    main()


