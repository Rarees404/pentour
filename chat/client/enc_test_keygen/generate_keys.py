# Import necessary modules from the cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# -----------------------------------------
# 🔐 Generate RSA Key Pair (4096-bit)
# -----------------------------------------
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used public exponent
    key_size=4096           # Key size in bits (4096 for strong security)
)

# -----------------------------------------
# 📝 Serialize and Save Private Key (Client-Side Only)
# -----------------------------------------
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,                      # Encode key in PEM format
    format=serialization.PrivateFormat.PKCS8,                 # Use PKCS8 standard format
    encryption_algorithm=serialization.NoEncryption()         # No password protection
)

# Write the private key to a file (keep this secure and never share)
with open("private_key.pem", "wb") as private_file:
    private_file.write(private_pem)

# -----------------------------------------
# 🌐 Serialize and Save Public Key (Can Be Shared)
# -----------------------------------------
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,                      # Encode key in PEM format
    format=serialization.PublicFormat.SubjectPublicKeyInfo    # Standard format for public key
)

# Write the public key to a file (this can be sent to the server or shared)
with open("public_key.pem", "wb") as public_file:
    public_file.write(public_pem)

# -----------------------------------------
# ✅ Status Messages
# -----------------------------------------
print("🔑 RSA Key Pair Generated!")
print("✅ Private Key: private_key.pem (DO NOT SHARE)")
print("✅ Public Key: public_key.pem (Send to Server)")
