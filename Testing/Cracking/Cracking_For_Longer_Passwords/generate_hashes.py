import os
from django.conf import settings
from django.contrib.auth.hashers import make_password

# Setup
#This file is to prehash the candidate passwords. In our case we assume that the hashed version of the passwords are stolen
#So we need to have a list of hashed passwords. This file is to do that.
settings.configure(
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes"],
    PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"],
)
import django
django.setup()

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
input_file = os.path.join(BASE_DIR, "user_passwords.txt")
output_file = os.path.join(BASE_DIR, "user_password_hashes.txt")

# Load passwords
with open(input_file, "r", encoding="utf-8") as f:
    passwords = [line.strip() for line in f if line.strip()]

# Hash and save
with open(output_file, "w", encoding="utf-8") as f:
    for pw in passwords:
        hash_val = make_password(pw)
        f.write(f"{pw}:{hash_val}\n")  # Save plaintext + hash (optional)
        print(f" Hashed: {pw}")

print(f"\n All hashes saved to: {output_file}")
