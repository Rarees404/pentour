import requests
import os
import json

def register_user(username, password):
    try:
        # -----------------------------------------
        # 🔑 Load Public Key (used for secure identity)
        # -----------------------------------------
        public_key_path = os.path.join('keys', 'public_key.pem')  # Path to public key file

        # Check if public key file exists
        if not os.path.exists(public_key_path):
            raise FileNotFoundError("Public key not found. Generate keys first!")

        # Read public key from file
        with open(public_key_path, "r") as file:
            public_key = file.read()

        # -----------------------------------------
        # 📦 Prepare User Registration Data
        # -----------------------------------------
        data = {
            "username": username,
            "password": password,
            "public_key": public_key.strip()  # Remove any trailing whitespace/newlines
        }

        # -----------------------------------------
        # 🌐 Send POST Request to Django Server
        # -----------------------------------------
        response = requests.post(
            "http://127.0.0.1:8000/chat/register/",  # Server endpoint
            json=data,                                # Send data as JSON
            headers={'Content-Type': 'application/json'}  # Set proper content type
        )

        # -----------------------------------------
        # ✅ Handle Server Response
        # -----------------------------------------
        if response.status_code == 201:  # HTTP 201 = Created
            print("✅ User registered successfully!")
            return True
        else:
            print(f"Registration Error: {response.status_code}")
            print(f"Server Response: {response.text}")
            return False

    # -----------------------------------------
    # ⚠️ Error Handling for Various Failure Cases
    # -----------------------------------------
    except requests.RequestException as e:
        print(f"Network Error: {e}")
        return False
    except FileNotFoundError as e:
        print(f"Key Error: {e}")
        return False
    except json.JSONDecodeError:
        print("Invalid JSON response from server")
        return False

# -----------------------------------------
# 🚀 Run Script if Called Directly
# -----------------------------------------
if __name__ == "__main__":
    register_user("alice", "strongpassword")
