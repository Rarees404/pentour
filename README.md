# Pentour

[https://pengincontour.xyz](https://pengincontour.xyz)

Pentour is an anonymous, real-time chat platform with end-to-end RSA encryption. Messages are always stored encrypted in the database and decrypted using the user's private key before display.

---

## 🛠 Setup Instructions

### 1. Install Python, Django, and Ngrok

Make sure Python is installed on your machine.  
Install Django and dependencies using:

### 2. Install Requirements TEXT

Run the command ```pip install -r requirements.txt```

### 3. Install PostgreSQL

Make sure PostgreSQL is installed and running. **Please do not forget the password you set in the setup, as you need this to launch the databases you set up.**

``Download``:
https://www.postgresql.org/download/

### 4. Create PostgreSQL Database and User

**- Launch pgAdmin4, then:**
    **a. Create a new database:**
    - Expand the server tree
    - Right-click on "Databases" → Create → Database
    - Name it as```my_database```

    **b. Create a login role:**
    - Scroll to "Login/Group Roles"
    - Right-click → Create → Login/Group Role (name it as ```myproject_user```)
    - Go to the Definition tab → set password to ```mysecretpassword```
    - Go to the Privileges tab → enable all permissions

### 4. Apply Migrations and Start the Django Development Server

**Run the following to set up your database schema:**
- python manage.py migrate
- python manage.py runserver

**You can now access the app at:**
- http://127.0.0.1:8000/ (as stated in the terminal)