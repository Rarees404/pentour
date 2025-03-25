from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

class MessageEncryptor:
    def __init__(self):
        """
        Initialize the MessageEncryptor with RSA key generation
        """
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        self.public_key = self.private_key.public_key()

    def encrypt_message(self, message):
        """
        Encrypt a plain text message using RSA public key

        Args:
            message (str): Plain text message to encrypt

        Returns:
            str: Base64 encoded encrypted message
        """
        try:
            # Convert message to bytes
            message_bytes = message.encode('utf-8')

            # Encrypt the message
            encrypted_message = self.public_key.encrypt(
                message_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Return base64 encoded encrypted message
            return base64.b64encode(encrypted_message).decode('utf-8')

        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def decrypt_message(self, encrypted_message):
        """
        Decrypt an encrypted message using RSA private key

        Args:
            encrypted_message (str): Base64 encoded encrypted message

        Returns:
            str: Decrypted plain text message
        """
        try:
            # Decode base64 encrypted message
            encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))

            # Decrypt the message
            decrypted_message = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Return decrypted message as string
            return decrypted_message.decode('utf-8')

        except Exception as e:
            print(f"Decryption Error: {e}")
            return None

    def save_keys(self, directory='keys'):
        """
        Save the generated public and private keys to files

        Args:
            directory (str): Directory to save keys
        """
        # Create directory if it doesn't exist
        os.makedirs(directory, exist_ok=True)

        # Save Private Key
        private_key_path = os.path.join(directory, 'private_key.pem')
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)

        # Save Public Key
        public_key_path = os.path.join(directory, 'public_key.pem')
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        print(f"Keys saved in {directory} directory")

def main():
    # Hardcoded messages for demonstration
    messages = [
        "Hello, this is a secret message!",
        "Meet me at the usual place.",
        "The project deadline is next week.",
        "Don't forget to buy milk on the way home."
    ]

    # Create an instance of MessageEncryptor
    encryptor = MessageEncryptor()

    # Save keys for future use
    encryptor.save_keys()

    # Encrypt and decrypt each message
    for message in messages:
        print("\n--- Message Processing ---")
        print(f"Original Message: {message}")

        # Encrypt the message
        encrypted_msg = encryptor.encrypt_message(message)
        print(f"Encrypted Message: {encrypted_msg}")

        # Decrypt the message
        decrypted_msg = encryptor.decrypt_message(encrypted_msg)
        print(f"Decrypted Message: {decrypted_msg}")

        # Verify encryption and decryption
        assert message == decrypted_msg, "Decryption failed!"

if __name__ == "__main__":
    main()