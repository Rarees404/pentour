# README: Message Signature Feature

## Introduction

This README details the integration of a digital signature mechanism into the existing chat application. The signature feature ensures integrity and non-repudiation of messages by allowing recipients to verify that messages have not been tampered with and indeed originated from the claimed sender.

---

## Background & Purpose

In a secure chat system, encrypting messages provides confidentiality, but does not guarantee integrity or authenticity. An attacker who intercepts and modifies ciphertext could cause the receiver to decrypt altered plaintext without detection. By digitally signing messages:

- **Integrity**: Any modification to the message will result in signature verification failure.
- **Authenticity**: Recipients can confirm the sender’s identity using the sender’s public key.
- **Non-Repudiation**: Senders cannot deny having sent a message.

We use **RSA-PSS** with **SHA-256** for signature generation and verification, alongside existing AES-GCM encryption for message confidentiality.

---

## Cryptographic Concepts

1. **AES-GCM** (Advanced Encryption Standard with Galois/Counter Mode)  
   - Provides confidentiality and built-in integrity (via authentication tag) for encrypted data.
2. **RSA-PSS** (Probabilistic Signature Scheme)  
   - A standardized RSA signature scheme that adds randomness to signatures and is resistant to certain attacks.
3. **SHA-256**  
   - A cryptographic hash function used to produce a fixed-size digest of the plaintext prior to signing.

---

## System Overview

1. **Signing**: Sign the plaintext message using the sender’s private RSA key.
2. **AES Encryption**: Encrypt the plaintext message with a randomly generated 256-bit AES key in GCM mode.
3. **RSA Encryption**: Encrypt the AES key with the recipient’s public RSA key.
4. **Storage**: Save the ciphertext, AES nonce, GCM tag, encrypted AES key, and Base64-encoded digital signature in the database.
5. **Retrieval**: On message fetch, RSA-decrypt the AES key, AES-decrypt the message, then verify the signature with the sender’s public RSA key. Flag any tampering.

---

## Setup & Installation

1. **Install Dependencies**  
   ```bash
   pip install pycryptodome
   ```

2. **Model Migration**  
   - Add a `signature` field to `chat/models.py`:
     ```python
     signature = models.TextField(null=True, blank=True)
     ```
   - Create and apply migrations:
     ```bash
     python manage.py makemigrations chat
     python manage.py migrate chat
     ```

3. **Generate RSA Key Pairs**  
   Store each user’s key pair in `chat/client/enc_test_keygen/static/keys/`:
   ```bash
   openssl genpkey -algorithm RSA -out alice_private.pem -pkeyopt rsa_keygen_bits:2048
   openssl rsa -pubout -in alice_private.pem -out alice_public.pem
   ```
   Repeat for each user (`bob_private.pem`, `bob_public.pem`, etc.).

4. **Logging Configuration**  
   Enable detailed logs in `settings.py` or at top of `views.py`:
   ```python
   import logging

   logging.basicConfig(
       level=logging.DEBUG,
       format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
   )
   ```

---

## Code Walkthrough

### 1. Model Extension (`chat/models.py`)
```python
class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_text = models.TextField()
    encrypted_symmetric_key = models.TextField()
    aes_nonce = models.TextField()
    aes_tag = models.TextField(null=True, blank=True)
    signature = models.TextField(null=True, blank=True)  # Digital signature field
    timestamp = models.DateTimeField(auto_now_add=True)
```

### 2. Cryptographic Utilities (`RSAEncryptor.py`)
```python
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def generate_aes_key() -> bytes:
    return get_random_bytes(32)

def encrypt_with_aes(key: bytes, plaintext: str) -> dict:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        'ciphertext': base64.b64encode(ct).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
    }

def decrypt_with_aes(key: bytes, data: dict) -> str:
    ct = base64.b64decode(data['ciphertext'])
    nonce = base64.b64decode(data['nonce'])
    tag = base64.b64decode(data['tag'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode()

def encrypt_aes_key_with_rsa(pub_pem: str, aes_key: bytes) -> str:
    pub = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(pub)
    enc_key = cipher.encrypt(aes_key)
    return base64.b64encode(enc_key).decode()

def decrypt_aes_key_with_rsa(priv_pem: str, enc_key_b64: str) -> bytes:
    enc = base64.b64decode(enc_key_b64)
    priv = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(enc)

def sign_message(priv_pem: str, message: str) -> str:
    key = RSA.import_key(priv_pem)
    h = SHA256.new(message.encode())
    signer = pss.new(key)
    sig = signer.sign(h)
    return base64.b64encode(sig).decode()

def verify_signature(pub_pem: str, message: str, signature_b64: str) -> bool:
    key = RSA.import_key(pub_pem)
    h = SHA256.new(message.encode())
    verifier = pss.new(key)
    sig = base64.b64decode(signature_b64)
    try:
        verifier.verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False
```

### 3. Send Message View (`chat/views.py`)
- **Flow**:
  1. Generate AES key.
  2. Encrypt plaintext with AES-GCM.
  3. Encrypt AES key with recipient’s RSA public key.
  4. Sign plaintext with sender’s RSA private key.
  5. Save fields including `signature`.
- **Logging**: `logger.debug()` after each step.

### 4. Get Messages View
- **Flow**:
  1. Decrypt AES key with recipient’s private key.
  2. Decrypt ciphertext with AES-GCM.
  3. Verify signature with sender’s public key.
  4. Prepend `[Tampered]` if verification fails.

---

## Flow Diagram
```plaintext
User A                              Database                            User B
  |                                     |                                   |
  |--[1] Sign plaintext→sigA------------>|                                   |
  |                                     |                                   |
  |--[2] AES encrypt→ct, nonce, tag----->|                                   |
  |                                     |                                   |
  |--[3] RSA encrypt AES key→encAESKey-->|                                   |
  |                                     |                                   |
  |--[4] Store {ct,nonce,tag,encAESKey,sigA}------------------------------→ |
  |                                     |                                   |
  |<--[5] Fetch messages---------------------------------------------←     |
  |                                     |                                   |
  |--[6] Decrypt AES key←encAESKey------|                                   |
  |--[7] AES decrypt←{ct,nonce,tag}→pt  |                                   |
  |--[8] Verify signature(pubA,pt,sigA)|                                   |
  |<--[9] Return pt or [Tampered] pt----|                                   |
```

---

## Error Handling & Testing

- **Migrations**: Ensure signature column exists.
- **Logs**: Review DEBUG-level logs for each crypto step.
- **Tampering test**: Modify signature or ciphertext in DB; retrieval should flag tampering.
- **Unit tests**: Cover sign→verify and encrypt→decrypt+verify.

---

## Troubleshooting

- **Signature column missing**: `makemigrations` + `migrate`.
- **Key files**: Verify PEM paths under `static/keys/`.
- **Logs not visible**: Set `logging.basicConfig(level=logging.DEBUG)`.

---

## File Structure

```
chat/
├── models.py  # Message.signature field added
├── views.py   # SendMessageView & GetMessagesView updated
└── client/
    └── enc_test_keygen/
        ├── static/keys/       # PEM key files
        └── RSAEncryptor.py    # Crypto utils
```
