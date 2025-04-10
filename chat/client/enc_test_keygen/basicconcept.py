from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os
from cryptography.hazmat.backends import default_backend

class MessageEncryptor:
    def __init__(self, private_path='keys/private_key.pem', public_path='keys/public_key.pem'):
        """
        Load RSA key pair from files. If not found, generate and save them.
        """
        # Load private key
        if os.path.exists(private_path):
            with open(private_path, 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            self.save_keys(os.path.dirname(private_path))

        # Load public key
        if os.path.exists(public_path):
            with open(public_path, 'rb') as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        else:
            self.public_key = self.private_key.public_key()

    def encrypt_message(self, message):
        try:
            message_bytes = message.encode('utf-8')
            encrypted = self.public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def decrypt_message(self, encrypted_message):
        try:
            encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"Decryption Error: {e}")
            return None

    def save_keys(self, directory='keys'):
        os.makedirs(directory, exist_ok=True)

        private_path = os.path.join(directory, 'private_key.pem')
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_path, 'wb') as f:
            f.write(private_pem)

        public_path = os.path.join(directory, 'public_key.pem')
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_path, 'wb') as f:
            f.write(public_pem)
