# Pentour

pengincontour.xyz

1-Install Python & Django and Nrok

Make sure you have Python installed.

Install Django (and any other dependencies) via pip install -r requirements.txt

2- At settings.py add your public ip at allowed hosts.

3- Install PostgreSQL: Make sure PostgreSQL is installed and running on your machine.

4- update username at settings.py Databases

5- Open pdAdmin4 (it is installed in your device with postgrade)

    - Expand server and right click on databases to create a database.
    - Then scroll down to create a login/group role (right click -> create). Then add a name/password (on definition tab) and give all the previliges (in privileges tab).

6- Then go to settings.py in the project folder and change the data to what you have just set.
    
    What it should look like:

    DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'my_database'),
        'USER': os.environ.get('POSTGRES_USER', 'myproject_user'),  # Change from 'user'
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'mysecretpassword'),
        'HOST': os.environ.get('POSTGRES_HOST', 'localhost'),
        'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    }
}

7- run python manage.py migrate

8- run python manage.py runserver

9- go to the link ex: https//190.304304... : 8080

10- Use different browsers to chat not the same one

Note: If you get bad request errors GPT them, easiest way is this.



