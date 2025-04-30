import os
import json
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# -----------------------------------------
# 🔐 Generate and Save RSA Key Pair (Per User)
# -----------------------------------------
def generate_keys_for_user(username):
    # Create key directory if it doesn't exist
    os.makedirs("user_keys", exist_ok=True)

    # Generate a new 4096-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # Serialize private key (DO NOT SHARE THIS)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key securely
    with open(f"user_keys/{username}_private.pem", "wb") as f:
        f.write(private_pem)

    # Serialize public key (CAN BE SHARED)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save public key
    with open(f"user_keys/{username}_public.pem", "wb") as f:
        f.write(public_pem)

    # Return public key string to send to server
    return public_pem.decode("utf-8").strip()


# -----------------------------------------
# 🌐 Register User with Server
# -----------------------------------------
def register_user(username, password):
    try:
        # Generate unique RSA key pair for this user
        public_key = generate_keys_for_user(username)

        # Prepare registration payload
        data = {
            "username": username,
            "password": password,
            "public_key": public_key
        }

        # Send POST request to server
        response = requests.post(
            "http://127.0.0.1:8000/chat/register/",
            json=data,
            headers={'Content-Type': 'application/json'}
        )

        # Handle server response
        if response.status_code == 201:
            print("✅ User registered successfully!")
            return True
        else:
            print(f"❌ Registration failed: {response.status_code}")
            print(f"Server Response: {response.text}")
            return False

    except Exception as e:
        print(f"⚠️ Error: {e}")
        return False


# -----------------------------------------
# 🚀 Run the Script
# -----------------------------------------
if __name__ == "__main__":
    register_user("alice", "strongpassword")

