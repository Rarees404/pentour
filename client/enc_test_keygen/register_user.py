import requests
import os
import json

def register_user(username, password):
    try:
        # Load public key
        public_key_path = os.path.join('keys', 'public_key.pem')

        if not os.path.exists(public_key_path):
            raise FileNotFoundError("Public key not found. Generate keys first!")

        with open(public_key_path, "r") as file:
            public_key = file.read()

        # User Registration Data
        data = {
            "username": username,
            "password": password,
            "public_key": public_key.strip()  # Remove any trailing whitespace
        }

        # Send Data to Django Server
        response = requests.post(
            "http://127.0.0.1:8000/chat/register/",
            json=data,
            headers={'Content-Type': 'application/json'}
        )

        # Enhanced error handling
        if response.status_code == 201:
            print("✅ User registered successfully!")
            return True
        else:
            print(f"Registration Error: {response.status_code}")
            print(f"Server Response: {response.text}")
            return False

    except requests.RequestException as e:
        print(f"Network Error: {e}")
        return False
    except FileNotFoundError as e:
        print(f"Key Error: {e}")
        return False
    except json.JSONDecodeError:
        print("Invalid JSON response from server")
        return False

if __name__ == "__main__":
    register_user("alice", "strongpassword")