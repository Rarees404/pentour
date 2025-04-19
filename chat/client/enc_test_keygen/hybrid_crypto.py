from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key():
    return get_random_bytes(32)  # AES-256

def encrypt_with_aes(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_with_aes(aes_key, encrypted_data):
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    tag = base64.b64decode(encrypted_data["tag"])
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def encrypt_aes_key_with_rsa(public_key_pem, aes_key):
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode()

def decrypt_aes_key_with_rsa(private_key_pem, encrypted_key_b64):
    encrypted_key = base64.b64decode(encrypted_key_b64)
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)
