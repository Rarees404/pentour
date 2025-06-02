import os
import time
import django
from django.conf import settings
from django.contrib.auth.hashers import check_password
from tqdm import tqdm

#Setupp
settings.configure(
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
    ],
    PASSWORD_HASHERS=["django.contrib.auth.hashers.PBKDF2PasswordHasher"],
)
django.setup()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths
hash_file = os.path.join(BASE_DIR, "15length_passwords_hashes.txt")
rockyou_file = os.path.join(BASE_DIR, "15LENGTHPASSWORD.txt")

#Load pre-hashed user passwords (format: plaintext:hash)
with open(hash_file, "r", encoding="utf-8") as f:
    hashed_passwords = [line.strip().split(":", 1) for line in f if ":" in line]

#Load attack wordlist
with open(rockyou_file, "r", encoding="latin-1") as f:
    rockyou_passwords = [line.strip() for line in f if len(line.strip()) > 15]

#Start timing
start_time = time.time()

#Dictionary attack with progress bar ( To make waiting bearable )
matched = []

print(f" Starting dictionary attack on {len(hashed_passwords)} passwords using {len(rockyou_passwords)} guesses...\n")

for user_password, hashed in tqdm(hashed_passwords, desc="Cracking", unit="password"):
    for guess in rockyou_passwords:
        if check_password(guess, hashed):
            print(f"!!! Cracked: '{user_password}' matched with '{guess}'")
            matched.append((user_password, guess))
            break
    else:
        print(f" Not cracked: '{user_password}'")

#End timing
end_time = time.time()
duration = end_time - start_time
minutes = int(duration // 60)
seconds = int(duration % 60)

#Final report
total = len(hashed_passwords)
cracked = len(matched)
success_rate = (cracked / total) * 100

print("\n Attack Summary")
print(f"Total Passwords:     {total}")
print(f"Cracked Passwords:   {cracked}")
print(f"Success Rate:        {success_rate:.2f}%")
print(f"Time Taken:          {minutes} minutes, {seconds} seconds")
