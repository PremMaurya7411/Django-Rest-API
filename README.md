
# Ssapi Python Rest API's## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`API_KEY` : http://127.0.0.1:8000/api

Database Details

`HOST` : Database Hostname

`PORT ` : Database Port Number 

`DB_USER` : Database User Name

`DB_PASSWORD ` : Database User Password 

SMPT  Details

`bakendtype` : True

`EMAIL_HOST ` : EMAIL_HOST

`EMAIL_PORT` : EMAIL_PORT 

`EMAIL_USE_TLS ` : True

`EMAIL_HOST_USER ` : EMAIL_HOST_USER/Email Address

`EMAIL_HOST_PASSWORD ` : EMAIL_HOST_PASSWORD
## Run Locally

Clone the project

```bash
  git clone https://github.com/exoticaitsolutions/ssapi.git
```

Go to the project directory

```bash
  cd ssapi
```
Create Virtual Environment

Windows:

```bash
py -m venv env
```
Unix/MacOS/Linux:

```bash
sudo python3 -m venv env
```
Then you have to activate the environment, by typing this command:

Windows:

```bash
env\Scripts\activate.bat
```
Unix/MacOS/LInux:

```bash
source env/bin/activate
```

Install dependencies

```bash
  pip install -r requirements.txt
```
Then Create the .env File To Configration the Database and mail 

Setup the Database with db name "django_rest_api" 

```bash
HOST=localhost
PORT=3306
DB_NAME=DB_NAME
DB_USER=DB_USER
DB_PASSWORD=DB_PASSWORD
```
Setup the Email SMPT
```bash
BACKEND =True 
EMAIL_HOST=EMAIL_HOST
EMAIL_PORT=EMAIL_PORT
EMAIL_USE_TLS=True/False
EMAIL_HOST_USER=EMAIL_HOST_USER
EMAIL_HOST_PASSWORD=EMAIL_HOST_PASSWORD
```

Then After make a make  migrate using the following command 

Windows:

```bash
python manage.py makemigrations api
```
Unix/MacOS/LInux:

```bash
python3 manage.py makemigrations api
```

Then run the migrate command to create the tables in the database 

Windows:

```bash
python manage.py migrate

```
Unix/MacOS/LInux:

```bash
python3 manage.py migrate
```
Start the server

Windows:

```bash
python manage.py runserver

```
Unix/MacOS/LInux:

```bash
python3 manage.py runserver

```
Note : 
if any case  Create the Super user then used the command 
Note name should be added by admin 

Windows:

```bash
python manage.py createsuperuser 

```
Unix/MacOS/LInux:

```bash
python3 manage.py createsuperuser 
```

Then After Assign the permission and role to perticular 

Windows:

```bash
python manage.py assign_superuser_permissions


```
Unix/MacOS/LInux:

```bash
python3 manage.py assign_superuser_permissions
```

## Tech Stack

**Server:** Mysql, Django ,Python 

