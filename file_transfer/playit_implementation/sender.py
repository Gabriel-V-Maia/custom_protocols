
"""
UDP File Transfer - Sender (POC)
Protocolo stop-and-wait com checksums Blake3.

Uso:
    pip install blake3
    python sender.py <arquivo> <host> <porta>
"""

import socket
import struct
import sys
import time
import os
import blake3

CHUNK_SIZE    = 1400 
TIMEOUT       = 2.0 
MAX_RETRIES   = 10
HASH_LEN      = 32 

MSG_HELLO  = 0x01
MSG_READY  = 0x02
MSG_CHUNK  = 0x03
MSG_ACK    = 0x04
MSG_NACK   = 0x05
MSG_FIN    = 0x06
MSG_DONE   = 0x07
MSG_ERR    = 0x08


def pack_hello(filename: str, filesize: int, file_hash: bytes) -> bytes:
    """
    HELLO: tipo(1) | filesize(8) | hash_arquivo(32) | len_nome(2) | nome
    """
    name_bytes = filename.encode("utf-8")
    return struct.pack("!BQH", MSG_HELLO, filesize, len(name_bytes)) + file_hash + name_bytes


def pack_chunk(seq: int, data: bytes, chunk_hash: bytes) -> bytes:
    """
    CHUNK: tipo(1) | seq(4) | len_data(2) | hash_chunk(32) | data
    """
    return struct.pack("!BIH", MSG_CHUNK, seq, len(data)) + chunk_hash + data


def pack_fin(total_chunks: int) -> bytes:
    """
    FIN: tipo(1) | total_chunks(4)
    """
    return struct.pack("!BI", MSG_FIN, total_chunks)


def unpack_type(msg: bytes) -> int:
    return struct.unpack("!B", msg[:1])[0]


def unpack_ack_nack(msg: bytes) -> int:
    """ACK/NACK: tipo(1) | seq(4)"""
    return struct.unpack("!BI", msg[:5])[1]

def send_file(filepath: str, host: str, port: int):
    if not os.path.isfile(filepath):
        print(f"[ERRO] Arquivo não encontrado: {filepath}")
        sys.exit(1)

    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)

    print(f"[INFO] Calculando hash do arquivo ({filesize} bytes)...")
    with open(filepath, "rb") as f:
        file_hash = blake3.blake3(f.read()).digest()
    print(f"[INFO] Hash Blake3: {file_hash.hex()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    addr = (host, port)

    print(f"[INFO] Enviando HELLO para {host}:{port}...")
    hello_pkt = pack_hello(filename, filesize, file_hash)

    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(hello_pkt, addr)
        try:
            data, _ = sock.recvfrom(64)
            if unpack_type(data) == MSG_READY:
                print("[INFO] Receiver pronto. Iniciando transferência...")
                break
        except socket.timeout:
            print(f"[WARN] Timeout no HELLO, tentativa {attempt}/{MAX_RETRIES}")
    else:
        print("[ERRO] Receiver não respondeu ao HELLO.")
        sys.exit(1)

    total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
    start_time = time.time()

    with open(filepath, "rb") as f:
        for seq in range(total_chunks):
            data = f.read(CHUNK_SIZE)
            chunk_hash = blake3.blake3(data).digest()
            chunk_pkt = pack_chunk(seq, data, chunk_hash)

            for attempt in range(1, MAX_RETRIES + 1):
                sock.sendto(chunk_pkt, addr)
                try:
                    resp, _ = sock.recvfrom(64)
                    rtype = unpack_type(resp)
                    rseq  = unpack_ack_nack(resp)

                    if rtype == MSG_ACK and rseq == seq:
                        pct = (seq + 1) / total_chunks * 100
                        elapsed = time.time() - start_time
                        speed = ((seq + 1) * CHUNK_SIZE) / elapsed / 1024
                        print(f"\r[{pct:5.1f}%] chunk {seq+1}/{total_chunks} | {speed:.1f} KB/s", end="", flush=True)
                        break
                    elif rtype == MSG_NACK and rseq == seq:
                        print(f"\n[WARN] NACK no chunk {seq}, retransmitindo... (tentativa {attempt})")
                except socket.timeout:
                    print(f"\n[WARN] Timeout no chunk {seq}, tentativa {attempt}/{MAX_RETRIES}")
            else:
                print(f"\n[ERRO] Falha permanente no chunk {seq}. Abortando.")
                sock.close()
                sys.exit(1)

    print() 

    fin_pkt = pack_fin(total_chunks)
    for attempt in range(1, MAX_RETRIES + 1):
        sock.sendto(fin_pkt, addr)
        try:
            resp, _ = sock.recvfrom(64)
            if unpack_type(resp) == MSG_DONE:
                elapsed = time.time() - start_time
                print(f"[OK] Transferência concluída em {elapsed:.2f}s")
                print(f"[OK] Receiver confirmou integridade do arquivo.")
                break
            elif unpack_type(resp) == MSG_ERR:
                print("[ERRO] Receiver rejeitou o arquivo (hash mismatch).")
                sys.exit(1)
        except socket.timeout:
            print(f"[WARN] Timeout no FIN, tentativa {attempt}/{MAX_RETRIES}")
    else:
        print("[WARN] Sem confirmação de DONE, mas transferência pode ter sido bem-sucedida.")

    sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python sender.py <arquivo> <host> <porta>")
        sys.exit(1)

    send_file(sys.argv[1], sys.argv[2], int(sys.argv[3]))
