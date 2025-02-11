import requests

# Load public key
with open("public_key.pem", "r") as file:
    public_key = file.read()

# User Registration Data
data = {
    "username": "alice",
    "password": "strongpassword",
    "public_key": public_key
}

# Send Data to Django Server
response = requests.post("http://127.0.0.1:8000/chat/register/", json=data)

if response.status_code == 201:
    print("✅ User registered successfully!")
else:
    print("❌ Error:", response.text)

