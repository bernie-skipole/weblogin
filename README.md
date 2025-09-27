# weblogin
An example web site with user login, using litestar, htmx, mako, alpinejs and w3.css

While creating a web control for an instrument, a user login was required. Since this may be useful for other projects, the login functionality with user editing was separated and made into this example project.

![Terminal screenshot](https://github.com/bernie-skipole/weblogin/raw/main/Screenshot.png)

To try it out, clone the project. Move to the weblogin directory and create a virtual environment (.venv in this example).

python3 -m venv .venv

Activate the environment:

source .venv/bin/activate

Install two dependencies:

pip install litestar[standard]

pip install litestar[mako]

Start the web site with:

uvicorn weblogin:app

If the initial sqlite file holding usernames does not exist, it will be created as users.sqlite with a single user 'admin' and password 'password!'. Note the exclamation mark. In real use I would place this server behind a reverse proxy, but have not included this in the example since it adds unnessecary detail.

Use your browser to connect to localhost:8000, follow the 'members' link, and login with the above user, and by following the 'edit' link, you can add further users.

Limitations: As it is originally intended for an instrument control, with few users, it uses a single web worker, an sqlite database to hold user details, and a Python dictionary to hold logged-in users. A database backup button does no more than create a copy of the sqlite database.

This is mainly intended to act as an example (and as a record for myself), I would also welcome any suggestions to improve it - but not to add functionality, as I would prefer it remains a limited example. Copy it and add further functionality for your own purposes if you want.

If it is required to expand this, then probably a database such as postgres would be needed, with the dictionary of logged in users replaced with a Redis or Valkey server.  The functions in file userdata.py would have to be changed accordingly. The alpinejs, htmx and css files under weblogin/static should also be replaced with later versions of these files from the appropriate projects if they have been updated.
