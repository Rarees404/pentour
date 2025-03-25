from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

class MessageEncryptor:
    def __init__(self):
        """
        Initialize the MessageEncryptor with RSA key generation.
        Generates a new 4096-bit RSA key pair (public + private).
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard public exponent
            key_size=4096           # Strong key size for secure encryption
        )
        self.public_key = self.private_key.public_key()  # Extract public key

    def encrypt_message(self, message):
        """
        Encrypt a plain text message using the RSA public key.

        Args:
            message (str): Plain text message to encrypt

        Returns:
            str: Base64 encoded encrypted message
        """
        try:
            # Convert string message to bytes
            message_bytes = message.encode('utf-8')

            # Encrypt using RSA with OAEP padding (secure padding for encryption)
            encrypted_message = self.public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 mask with SHA256
                    algorithm=hashes.SHA256(),                    # Main hash algorithm
                    label=None
                )
            )

            # Return encrypted message encoded in Base64 for safe printing/storage
            return base64.b64encode(encrypted_message).decode('utf-8')

        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def decrypt_message(self, encrypted_message):
        """
        Decrypt an encrypted message using the RSA private key.

        Args:
            encrypted_message (str): Base64 encoded encrypted message

        Returns:
            str: Decrypted plain text message
        """
        try:
            # Decode from Base64 to get original encrypted bytes
            encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))

            # Decrypt using RSA private key with OAEP padding
            decrypted_message = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Convert decrypted bytes back to string
            return decrypted_message.decode('utf-8')

        except Exception as e:
            print(f"Decryption Error: {e}")
            return None

    def save_keys(self, directory='keys'):
        """
        Save the generated RSA key pair to .pem files.

        Args:
            directory (str): Directory where the keys will be saved
        """
        # Ensure the directory exists
        os.makedirs(directory, exist_ok=True)

        # ----- Save Private Key -----
        private_key_path = os.path.join(directory, 'private_key.pem')
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,             # PEM format
            format=serialization.PrivateFormat.PKCS8,         # Standard format
            encryption_algorithm=serialization.NoEncryption() # No password
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)

        # ----- Save Public Key -----
        public_key_path = os.path.join(directory, 'public_key.pem')
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        print(f"🔑 Keys saved in '{directory}' directory")

def main():
    # 📨 Sample messages to test encryption and decryption
    messages = [
        "Hello, this is a secret message!",
        "Meet me at the usual place.",
        "The project deadline is next week.",
        "Don't forget to buy milk on the way home."
    ]

    # 🔐 Create an instance of MessageEncryptor and generate keys
    encryptor = MessageEncryptor()

    # 💾 Save keys to disk
    encryptor.save_keys()

    # 🔁 Encrypt and decrypt each message
    for message in messages:
        print("\n--- Message Processing ---")
        print(f"📝 Original Message: {message}")

        # Encrypt
        encrypted_msg = encryptor.encrypt_message(message)
        print(f"🔒 Encrypted Message: {encrypted_msg}")

        # Decrypt
        decrypted_msg = encryptor.decrypt_message(encrypted_msg)
        print(f"🔓 Decrypted Message: {decrypted_msg}")

        # ✅ Verify encryption-decryption cycle
        assert message == decrypted_msg, "❌ Decryption failed!"

if __name__ == "__main__":
    main()
