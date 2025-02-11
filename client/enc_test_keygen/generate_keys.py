from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096  # Strong security
)

# Save Private Key (Client-Side Only)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()  # No password encryption
)

with open("private_key.pem", "wb") as private_file:
    private_file.write(private_pem)

# Save Public Key (To Send to Server)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "wb") as public_file:
    public_file.write(public_pem)

print("🔑 RSA Key Pair Generated!")
print("✅ Private Key: private_key.pem (DO NOT SHARE)")
print("✅ Public Key: public_key.pem (Send to Server)")

