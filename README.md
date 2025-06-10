# Telepathy

**Telepathy** is an anonymous, real-time chat platform with end-to-end RSA encryption.  
Messages are **always stored encrypted** in the database and **decrypted using the user's private key** before being displayed. Digital signatures are also used for message integrity.

---

## 🔧 Setup Instructions

### 1. Clone the Repository 


```bash
git clone https://github.com/Rarees404/pentour.git

For server-side version: git switch Final_Product
For client-side version: git switch Final_ClientSide

cd pentour
```

---

### 2. Install Python 3

Make sure Python 3 is installed on your system.

#### macOS (Python 3 is usually pre-installed)

To upgrade:
```bash
brew install python
```

#### Linux/Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
```

#### Windows:

1. Download Python from: [https://www.python.org/downloads/](https://www.python.org/downloads/)
2. Run the installer, and **make sure to check** "Add Python to PATH".
3. Verify installation:
```cmd
python --version
```

---

### 3. Install PostgreSQL

Make sure PostgreSQL is installed and running on your system.

**Option A: Download Installer (Windows)**  
Download and run the PostgreSQL installer from the link (https://www.postgresql.org/download/) and follow the setup wizard instructions.

**Option B (macOS): Install via Homebrew**
```bash
brew install postgresql
initdb /usr/local/var/postgres
brew services start postgresql
brew services status postgresql
brew services stop postgresql //stop server after finish

```

**Option C (Linux/Ubuntu):**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo service postgresql start
sudo service postgresql stop //stop the server after you finish
```

---

### 4. Create Database and Role

Open a terminal or command prompt and enter the PostgreSQL shell:

#### macOS/Linux:
```bash
psql postgres
```

#### Windows (cmd):
```cmd
psql -U postgres
```

Then run the following commands **one by one** inside the PostgreSQL shell:

```sql
DROP DATABASE IF EXISTS my_database;
DROP ROLE IF EXISTS myproject_user;

CREATE ROLE myproject_user
  WITH LOGIN
  PASSWORD 'mysecretpassword'
  CREATEDB
  CREATEROLE
  INHERIT;

CREATE DATABASE my_database
  OWNER = myproject_user
  ENCODING = 'UTF8'
  LC_COLLATE = 'en_US.UTF-8'
  LC_CTYPE = 'en_US.UTF-8'
  TEMPLATE = template0;
```
If during the commands execution you notice a change (postgres=#   ->  postgres-#) type \r. 
After creating the role, you should see:
```
CREATE ROLE
```

After creating the database, you should see:
```
CREATE DATABASE
```

To quit the shell:
```sql
\q
```

---

### 5. Set Up the Python Environment

Navigate to the project folder:
```bash
cd pentour
```

Create and activate a virtual environment:

#### macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows (cmd):
```cmd
python -m venv venv
venv\Scripts\activate
```

---

### 6. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install colorlog django-postgrespool2 pillow channels==4.2.0 channels_redis psycopg2-binary
```

---

### 7. Apply Migrations

```bash
python manage.py makemigrations
python manage.py migrate
do empty the db: python manage.py flush
```

---

### 8. Start the Development Server

```bash
python manage.py runserver
```

---

## 🚀 Access the App

Once the server is running, open your browser and navigate to:
For more information read the "Developer Notes"
[http://127.0.0.1:8000/](http://127.0.0.1:8000/)

---

## 🧠 Developer Notes

> For testing purposes, we **recommend using an incognito/private tabs on different browser windows**.  
This ensures that localStorage (tokens/keys) is cleared between user sessions.  
If you're creating a new user after logout, make sure to open a new incognito window.
>

If you encounter errors during setup or usage, feel free to contact the developer:

📧 **r.boghean@student.maastrichuniversity.nl**
