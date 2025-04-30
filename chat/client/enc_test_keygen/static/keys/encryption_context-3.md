
# Detailed Encryption Logic in Django Chat Project

## Introduction

This document describes, in technical depth, how hybrid encryption (RSA + AES-GCM) is integrated into your Django chat project. It includes:

- RSA key generation and storage
- AES-GCM symmetric encryption
- RSA-OAEP key wrapping
- Step-by-step encryption/decryption flows
- Concrete examples for two users (Alice and Bob)
- Code snippets mapping to your project’s files

---

## 1. Key Generation and Storage

### 1.1 RSA Key Pair Generation

Using `generate_keys.py` with the Python `cryptography` library, we create a 4096-bit RSA key pair:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate private key
priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
# Derive public key
pub_key = priv_key.public_key()

# Serialize private key (PEM, PKCS8, no encryption shown)
priv_pem = priv_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key (PEM, SubjectPublicKeyInfo)
pub_pem = pub_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key.pem','wb') as f: f.write(priv_pem)
with open('public_key.pem','wb') as f: f.write(pub_pem)
```

- **private_key.pem**: Keep secret (client side or encrypted in DB).
- **public_key.pem**: Share with server or store in `User.public_key`.

### 1.2 Per-User Key Fields

In `chat/models.py`:

```python
class User(models.Model):
    username = models.CharField(...)
    public_key = models.TextField()       # PEM-encoded public key
    private_kyte = models.TextField()     # Encrypted PEM private key
```

Current code uses static PEM files under `client/enc_test_keygen/static/keys/`, but should be extended to load per-user.

---

## 2. Hybrid Encryption Overview

Hybrid encryption combines:

1. **AES-GCM** for fast data encryption (confidentiality + integrity).
2. **RSA-OAEP** to securely wrap (encrypt) the AES key.

### Why Hybrid?

- RSA on large messages is slow.
- AES handles large payloads efficiently.
- RSA secures the AES key exchange.

---

## 3. Message Sending Flow (Alice → Bob)

Alice writes a message "Hello Bob!" in the chat UI. The server’s `SendMessageView` performs:

1. **Generate a 256-bit AES key**  
   ```python
   from hybrid_crypto import generate_aes_key
   aes_key = generate_aes_key()  # 32 random bytes
   ```
2. **AES-GCM encrypt the plaintext**  
   ```python
   from hybrid_crypto import encrypt_with_aes
   result = encrypt_with_aes(aes_key, b"Hello Bob!")
   # result = {
   #   'ciphertext': b'...base64...',
   #   'nonce': b'...base64...',
   #   'tag': b'...base64...'
   # }
   ```
3. **Load Bob’s RSA public key**  
   ```python
   from django.contrib.auth import get_user_model
   User = get_user_model()
   bob = User.objects.get(username='bob')
   public_key_pem = bob.public_key  # load from DB
   ```
4. **Encrypt (wrap) the AES key with RSA-OAEP**  
   ```python
   from hybrid_crypto import encrypt_aes_key_with_rsa
   encrypted_key = encrypt_aes_key_with_rsa(public_key_pem, aes_key)
   # encrypted_key is base64(RSA_OAEP(aes_key))
   ```
5. **Persist to DB** (`Message` model):
   ```python
   Message.objects.create(
       sender=alice, recipient=bob,
       encrypted_text=result['ciphertext'],
       encrypted_symmetric_key=encrypted_key,
       aes_nonce=result['nonce'],
       aes_tag=result['tag']
   )
   ```

| Field                   | Stored Value                 |
|-------------------------|------------------------------|
| encrypted_text          | AES-GCM ciphertext (Base64)  |
| encrypted_symmetric_key | RSA-OAEP wrapped AES key     |
| aes_nonce               | AES-GCM nonce (Base64)       |
| aes_tag                 | AES-GCM tag (Base64)         |

---

## 4. Message Retrieval Flow (Bob reads)

Bob requests his messages via `GetMessagesView`. For each `Message`:

1. **Load Bob’s RSA private key**  
   ```python
   private_key_pem = decrypt_private_kyte(bob.private_kyte)
   ```
2. **RSA-OAEP unwrap AES key**  
   ```python
   from hybrid_crypto import decrypt_aes_key_with_rsa
   aes_key = decrypt_aes_key_with_rsa(private_key_pem, message.encrypted_symmetric_key)
   ```
3. **AES-GCM decrypt ciphertext**  
   ```python
   from hybrid_crypto import decrypt_with_aes
   plaintext = decrypt_with_aes(aes_key, {
       'ciphertext': message.encrypted_text,
       'nonce': message.aes_nonce,
       'tag': message.aes_tag
   })
   # plaintext == b"Hello Bob!"
   ```
4. Return plaintext in JSON response.

---

## 5. Two-User Example with Concrete Values

### 5.1 Setup

- Alice’s RSA key pair:  
  - public_key.pem_A  
  - private_key.pem_A  
- Bob’s RSA key pair:  
  - public_key.pem_B  
  - private_key.pem_B  

Alice’s DB record:
```sql
INSERT INTO chat_user (username, public_key, private_kyte) VALUES
('alice', '<PEM data_A>', '<encrypted PEM_A>');
```
Bob’s DB record similarly.

### 5.2 Alice → Bob: Encrypt “Hello Bob!”

- AES key (hex): `a1b2c3...f0`  
- AES-GCM nonce (Base64): `Q2hhdE5vbmNl`  
- AES-GCM tag (Base64): `VGFnVmFsdWU=`  
- AES ciphertext (Base64): `Q2lwaGVydGV4dA==`

Wrap AES key with Bob’s RSA:
- RSA-OAEP output (Base64): `UmFuZG9tU3ltbWV0cmljS2V5`

DB row:
| encrypted_text       | encrypted_symmetric_key   | aes_nonce    | aes_tag      |
|----------------------|---------------------------|--------------|--------------|
| Q2lwaGVydGV4dA==     | UmFuZG9tU3ltbWV0cmljS2V5  | Q2hhdE5vbmNl | VGFnVmFsdWU= |

### 5.3 Bob reads message

- RSA-OAEP unwrap yields AES key `a1b2c3...f0`
- AES-GCM decrypt returns `Hello Bob!`

---

## 6. Technical Considerations

- **OAEP padding**: RSA-OAEP with SHA-256 for semantic security.
- **AES-GCM**: 96-bit nonce, 128-bit tag.
- **Base64 encoding**: Ensures binary data safe in JSON/DB.
- **Key storage**: Move from static PEM to DB-backed fields; encrypt private_kyte at rest.
- **Key rotation**: Add `key_version` on `Message` to support multiple RSA keys.
- **Error handling**: Catch `InvalidTag` from AES, `ValueError` from RSA.

---

## 7. Mapping to Your Code Files

| Concept                       | File                                |
|-------------------------------|-------------------------------------|
| RSA key generation            | `client/enc_test_keygen/generate_keys.py` |
| AES & RSA helper functions    | `client/enc_test_keygen/hybrid_crypto.py` |
| Hybrid send/receive views     | `chat/views.py` (`SendMessageView`, `GetMessagesView`) |
| Models for keys & messages    | `chat/models.py` (`User`, `Message`) |

---


