# weblogin
A web login using litestar, htmx, mako, alpinejs and w3.css

create and activate a venv and:

pip install litestar[standard]

pip install litestar[mako]

start with

uvicorn weblogin:app

and the web site will run on port 8000. If the initial sqlite file holding usernames does not exist, it will be created with a single user 'admin' and password 'password!'.
