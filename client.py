import blake3
import socket
import json
from dataclasses import dataclass

@dataclass
class Packet:
    source: str
    name: str
    size: int
    checksum: str
    payload: bytes

    def to_bytes(self) -> bytes:
        header = {
            "source": self.source,
            "name": self.name,
            "size": self.size,
            "checksum": self.checksum,
        }
        header_json = json.dumps(header).encode("utf-8")
        header_len = len(header_json).to_bytes(4, "big")
        return header_len + header_json + self.payload

    @staticmethod
    def from_file(source: str, path: str):
        with open(path, "rb") as f:
            payload = f.read()

        checksum = blake3.blake3(payload).hexdigest()
        size = len(payload)
        name = path.split("/")[-1]

        return Packet(
            source=source,
            name=name,
            size=size,
            checksum=checksum,
            payload=payload
        )

def main():
    packet = Packet.from_file("192.168.0.5", "test.txt")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 6000))
        s.sendall(packet.to_bytes())


main() 
