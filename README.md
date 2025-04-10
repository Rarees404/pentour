# 🐧 Pentour

🔗 [https://pengincontour.xyz](https://pengincontour.xyz)

Pentour is an anonymous, real-time chat platform with end-to-end RSA encryption.  
Messages are **always stored encrypted** in the database and **decrypted using the user's private key** before being displayed.

---

## 🛠 Setup Instructions

### 1. Install Python, Django, and Ngrok

Make sure Python is installed on your machine.  
Install Django and dependencies using:

```bash
pip install django
# or install all dependencies via requirements.txt (see step 2)
```

---

### 2. Install Requirements

Install all Python dependencies with:

```bash
pip install -r requirements.txt
```

---

### 3. Install PostgreSQL

Ensure PostgreSQL is installed and running on your system.  
> ⚠️ **Do not forget the password you set during installation** — you'll need it to connect to the database.

📥 **Download:**  
[https://www.postgresql.org/download/](https://www.postgresql.org/download/)

---

### 4. Create PostgreSQL Database and User

Launch **pgAdmin4**, then follow these steps:

#### 📁 1. Create a new database:
- Expand the server tree
- Right-click on **Databases** → **Create** → **Database**
- Name it: `my_database`

#### 👤 2. Create a login role:
- Scroll to **Login/Group Roles**
- Right-click → **Create** → **Login/Group Role**
    - Name: `myproject_user`
- Go to the **Definition** tab → Set the password to: `mysecretpassword`
- Go to the **Privileges** tab → Enable **all permissions**

---

### 5. Apply Migrations and Start the Django Development Server

Run the following commands to set up your database schema and start the server:

```bash
python manage.py migrate
python manage.py runserver
```

---

### 🚀 Access the App

Once the server is running, open your browser and navigate to:

[http://127.0.0.1:8000/](http://127.0.0.1:8000/)
