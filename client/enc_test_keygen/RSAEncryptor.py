from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import base64



class RSAEncryptor:
    def __init__(self, public_key_path=None, private_key_path=None):
        """
        Initialize RSA Encryptor with optional key paths

        Args:
            public_key_path (str, optional): Path to public key file
            private_key_path (str, optional): Path to private key file
        """
        self.public_key = None
        self.private_key = None

        # Load public key if path provided
        if public_key_path and os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read())

        # Load private key if path provided
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

    def encrypt(self, message):
        """
        Encrypt a plain text message using the public key

        Args:
            message (str): Plain text message to encrypt

        Returns:
            str: Base64 encoded encrypted message
        """
        if not self.public_key:
            raise ValueError("Public key not loaded. Provide a valid public key path.")

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

    def decrypt(self, encrypted_message):
        """
        Decrypt an encrypted message using the private key

        Args:
            encrypted_message (str): Base64 encoded encrypted message

        Returns:
            str: Decrypted plain text message
        """
        if not self.private_key:
            raise ValueError("Private key not loaded. Provide a valid private key path.")

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

def main():
    # Example usage
    keys_dir = 'keys'
    public_key_path = os.path.join(keys_dir, 'public_key.pem')
    private_key_path = os.path.join(keys_dir, 'private_key.pem')

    # Create encryptor
    encryptor = RSAEncryptor(
        public_key_path=public_key_path,
        private_key_path=private_key_path
    )

    # Test encryption and decryption
    original_message = "Hello, this is a secret message!"
    print("Original Message:", original_message)

    # Encrypt
    encrypted_msg = encryptor.encrypt(original_message)
    print("Encrypted Message:", encrypted_msg)

    # Decrypt
    decrypted_msg = encryptor.decrypt(encrypted_msg)
    print("Decrypted Message:", decrypted_msg)

    # Verify
    assert original_message == decrypted_msg, "Decryption failed!"
    print("✅ Encryption and Decryption Successful!")

if __name__ == "__main__":
    main()