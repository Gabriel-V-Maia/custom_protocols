# Implementação com tunnel UDP usando playit

O plano gratuito do playit apenas deixa usar tunnel UDP, e não TCP.
Devido a limitações da minha provedora, não posso expor meu file server pra internet diretamente, então decidi criar uma alternativa usando UDP com checksums robustos via Blake3.

Eu chamo ele de **RUSP**.

---

# RUSP — Reliable UDP Simple Protocol

Protocolo simples de transferência de arquivos sobre UDP com verificação de integridade em dois níveis: por chunk (Blake3) e por arquivo completo (Blake3).

## Packet Layout

### HELLO (0x01)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  type=0x01    |                 filesize (8 bytes)            |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            name_len (2)       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                    file_hash blake3 (32 bytes)                |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    filename (variable)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### READY (0x02)
```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|  type=0x02    |
+-+-+-+-+-+-+-+-+
```

### CHUNK (0x03)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  type=0x03    |                   seq (4 bytes)               |
+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
|                                               |  data_len (2) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    chunk_hash blake3 (32 bytes)               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    data (variable, max 1400)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### ACK (0x04) / NACK (0x05)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  type=0x04/05 |                   seq (4 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### FIN (0x06)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  type=0x06    |               total_chunks (4 bytes)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### DONE (0x07) / ERR (0x08)
```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|  type=0x07/08 |
+-+-+-+-+-+-+-+-+
```

## Uso

```bash
pip install blake3

# Receiver
python receiver.py <porta> [pasta_destino]

# Sender
python sender.py <arquivo> <host> <porta>
```

## Dependências

- Python 3.10+
- [blake3](https://pypi.org/project/blake3/)
- [playit.gg](https://playit.gg) (tunnel UDP, plano gratuito)
