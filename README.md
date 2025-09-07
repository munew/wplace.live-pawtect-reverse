wplace.live Protection Reverse (Pawtect)
---

## Token Format

```
<ciphertext>.<nonce>
```

- **Ciphertext**: Encrypted data.
- **Nonce**: Random 24-byte value used for encryption.

---

## Encryption Details

- **Algorithm**: XChaCha20 Poly1305 (empty AEAD)
- **Key size**: 32 bytes
- **Nonce size**: 24 bytes
- **Key (base64)**:

  ```
  EzcTNxM3EzcTNxM3EzcTNxM3EzcTNxM3EzcTNxM3Ezc=
  ```

---

## Token Contents

### `/load` request
- Always sends literal value:
  ```
  i
  ```

### Place
Tokens contain the following structure:

```
[timestamp (4 bytes), 0, sha256(body), 0, 0, hosts]
```

- **timestamp (4 bytes)**: static timestamp (?)
- **0**: unknown
- **sha256(body)**: explicit (32 bytes)
- **0, 0**: unknown
- **hosts**: host array (e.g. [backend.wplace.live]) (important to note: lengths are stored using u32)