# Telepathy



Telepathy is an anonymous, real-time chat platform with end-to-end RSA encryption.  
Messages are **always stored encrypted** in the database and **decrypted using the user's private key** before being displayed, and also sigantures


## Setup Instructions


Clone repo:
git clone //repo link.

## Install PostgreSQL

Ensure PostgreSQL is installed and running on your system.
**Download:**  
[https://www.postgresql.org/download/](https://www.postgresql.org/download/)

OR  Download using homebrew:
1) brew install postgresql
2) initdb /usr/local/var/postgres
3) brew services start postgresql
4) verify is running: brew services status postgresql




OPEN NEW TERMINAL AND TYPE:
1) psql postgres
   you should enter postgres shell where you type commands and see something like this:
   postgres=#


1) COMMAND
   DROP DATABASE IF EXISTS my_database;

2)
DROP ROLE   IF EXISTS myproject_user;



postgres=# CREATE ROLE myproject_user
WITH LOGIN
PASSWORD 'mysecretpassword'
CREATEDB
CREATEROLE
INHERIT;

You should get: CREATE ROLE



postgres=# CREATE DATABASE my_database
OWNER      = myproject_user
ENCODING   = 'UTF8'
LC_COLLATE = 'en_US.UTF-8'
LC_CTYPE   = 'en_US.UTF-8'
TEMPLATE   = template0;

you should get: CREATE DATABASE

To quit shell:
\q


Then go into the project repository using cd:
command: cd pentour

CREATE VIRTUAL ENVIROMENT
python3 -m venv venv

ACTIVATE VIRTUAL ENVIRONMENT  
source venv/bin/activate


Install project dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install colorlog django-postgrespool2 pillow channels==4.2.0 channels_redis psycopg2-binary


Apply Django migrations
python manage.py migrate


Start the development server
python manage.py runserver


### 🚀 Access the App

Once the server is running, open your browser and navigate to:, 


[http://127.0.0.1:8000/](http://127.0.0.1:8000/)


DEVELOPER NOTES:
For using the app id recomend using icognito browsers, because the browser saves some tokens/keys,. If you log out and want to create a new user
be sure that you opened a new incognioto page for creating the new user. If during running you encounter erros, feel free to contact the developer via email:
r.boghean@student.maastrichuniversity.nl  refactor tis read me file, and do not modify the contend just make it better and give me the exact code to paste 