
"""
UDP File Transfer - Receiver (POC)
Protocolo stop-and-wait com checksums Blake3.

Uso:
    pip install blake3
    python receiver.py <porta> [pasta_destino]
"""

import socket
import struct
import sys
import os
import blake3

CHUNK_SIZE = 1400
HASH_LEN   = 32
TIMEOUT    = 30.0

MSG_HELLO  = 0x01
MSG_READY  = 0x02
MSG_CHUNK  = 0x03
MSG_ACK    = 0x04
MSG_NACK   = 0x05
MSG_FIN    = 0x06
MSG_DONE   = 0x07
MSG_ERR    = 0x08

def unpack_type(msg: bytes) -> int:
    return struct.unpack("!B", msg[:1])[0]


def unpack_hello(msg: bytes):
    """
    Retorna (filename, filesize, file_hash)
    HELLO: tipo(1) | filesize(8) | len_nome(2) | hash(32) | nome
    """
    filesize, name_len = struct.unpack("!QH", msg[1:11])
    file_hash = msg[11: 11 + HASH_LEN]
    filename  = msg[11 + HASH_LEN: 11 + HASH_LEN + name_len].decode("utf-8")
    return filename, filesize, file_hash


def unpack_chunk(msg: bytes):
    """
    Retorna (seq, data, chunk_hash)
    CHUNK: tipo(1) | seq(4) | len_data(2) | hash(32) | data
    """
    seq, data_len = struct.unpack("!IH", msg[1:7])
    chunk_hash = msg[7: 7 + HASH_LEN]
    data       = msg[7 + HASH_LEN: 7 + HASH_LEN + data_len]
    return seq, data, chunk_hash


def unpack_fin(msg: bytes) -> int:
    """FIN: tipo(1) | total_chunks(4)"""
    return struct.unpack("!BI", msg[:5])[1]


def pack_ack(seq: int) -> bytes:
    return struct.pack("!BI", MSG_ACK, seq)


def pack_nack(seq: int) -> bytes:
    return struct.pack("!BI", MSG_NACK, seq)


def pack_ready() -> bytes:
    return struct.pack("!B", MSG_READY)


def pack_done() -> bytes:
    return struct.pack("!B", MSG_DONE)


def pack_err() -> bytes:
    return struct.pack("!B", MSG_ERR)


def receive_files(port: int, dest_dir: str):
    os.makedirs(dest_dir, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(TIMEOUT)

    print(f"[INFO] Escutando na porta UDP {port}...")
    print(f"[INFO] Salvando arquivos em: {os.path.abspath(dest_dir)}")

    while True:
        try:
            msg, sender_addr = sock.recvfrom(65535)
        except socket.timeout:
            print("[INFO] Aguardando conexão...")
            continue

        if unpack_type(msg) != MSG_HELLO:
            print(f"[WARN] Pacote inesperado (tipo={unpack_type(msg):#x}), ignorando.")
            continue

        filename, filesize, expected_file_hash = unpack_hello(msg)
        total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE

        safe_name = os.path.basename(filename)
        dest_path = os.path.join(dest_dir, safe_name)

        print(f"\n[INFO] Nova transferência de {sender_addr}")
        print(f"[INFO] Arquivo : {safe_name} ({filesize} bytes, {total_chunks} chunks)")
        print(f"[INFO] Hash    : {expected_file_hash.hex()}")

        sock.sendto(pack_ready(), sender_addr)

        chunks: dict[int, bytes] = {} 
        expected_seq = 0

        while expected_seq < total_chunks:
            try:
                msg, addr = sock.recvfrom(65535)
            except socket.timeout:
                print(f"\n[WARN] Timeout esperando chunk {expected_seq}.")
                continue

            if addr != sender_addr:
                continue 

            mtype = unpack_type(msg)

            if mtype == MSG_CHUNK:
                seq, data, chunk_hash = unpack_chunk(msg)

                actual_hash = blake3.blake3(data).digest()
                if actual_hash != chunk_hash:
                    print(f"\n[WARN] Hash inválido no chunk {seq}! Enviando NACK.")
                    sock.sendto(pack_nack(seq), sender_addr)
                    continue

                if seq != expected_seq:
                    print(f"\n[WARN] Chunk fora de ordem: esperado {expected_seq}, recebido {seq}")
                    continue

                chunks[seq] = data
                sock.sendto(pack_ack(seq), sender_addr)
                expected_seq += 1

                pct = expected_seq / total_chunks * 100
                print(f"\r[{pct:5.1f}%] chunk {expected_seq}/{total_chunks}", end="", flush=True)

            elif mtype == MSG_HELLO:
                sock.sendto(pack_ready(), sender_addr)

        print() 

        try:
            msg, addr = sock.recvfrom(64)
            if unpack_type(msg) == MSG_FIN and addr == sender_addr:
                total_recv = unpack_fin(msg)
                print(f"[INFO] FIN recebido. Sender reporta {total_recv} chunks.")
        except socket.timeout:
            print("[WARN] FIN não recebido, verificando arquivo mesmo assim...")

        print("[INFO] Verificando integridade do arquivo...")
        hasher = blake3.blake3()
        with open(dest_path, "wb") as f:
            for i in range(total_chunks):
                chunk_data = chunks.get(i, b"")
                f.write(chunk_data)
                hasher.update(chunk_data)

        actual_file_hash = hasher.digest()

        if actual_file_hash == expected_file_hash:
            print(f"[OK] Arquivo salvo: {dest_path}")
            print(f"[OK] Integridade confirmada: {actual_file_hash.hex()}")
            sock.sendto(pack_done(), sender_addr)
        else:
            print(f"[ERRO] Hash mismatch!")
            print(f"       Esperado : {expected_file_hash.hex()}")
            print(f"       Recebido : {actual_file_hash.hex()}")
            sock.sendto(pack_err(), sender_addr)
            os.remove(dest_path)
            print(f"[INFO] Arquivo corrompido removido.")

        print(f"\n[INFO] Pronto para próxima transferência.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python receiver.py <porta> [pasta_destino]")
        sys.exit(1)

    port     = int(sys.argv[1])
    dest_dir = sys.argv[2] if len(sys.argv) > 2 else "./recebidos"

    receive_files(port, dest_dir)
