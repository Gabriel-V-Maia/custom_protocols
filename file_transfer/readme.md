# Transferencia de dados

Esse protocolo é feito para exclusivamente transferencia de arquivos, utilizando BLAKE3 para checksum
Ele é relativamente simples, seguindo a seguinte estrutura:

```
+--------------------+-----------------------+
| 4 bytes header_len |  header_json          |
+--------------------+-----------------------+
|       12 bytes nonce                       |
+--------------------------------------------+
| 4 bytes payload_len | encrypted_payload    |
+--------------------+-----------------------+
```

