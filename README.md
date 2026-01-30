# weblogin
An example web site with user login, using litestar, htmx, mako and w3.css

While creating a web control for an instrument, a user login feature was required. Since this may be useful for other projects, the user login and administration was separated and made into this example project. A screenshot is shown below:

![Terminal screenshot](https://github.com/bernie-skipole/weblogin/raw/main/Screenshot.png)

To try it out, clone the project. Move to the top weblogin directory and create a virtual environment (.venv in this example).

python3 -m venv .venv

Activate the environment:

source .venv/bin/activate

Install dependencies:

pip install litestar[standard]

pip install litestar[mako]

Start the web site, either with:

uvicorn weblogin:app

Or with:

python3 -m weblogin


The result of python3 -m weblogin --help is:

    usage: weblogin [options]

    Web server illustrating login capabilities.

    options:
      -h, --help   show this help message and exit
      --port PORT  Listening port of the web server.
      --host HOST  Hostname/IP of the web server.

    If not set here, the host and port defaults are 'localhost:8000'.
    The database file holds user configuration, and is initially
    created with user 'admin' and password 'password!', which can
    be changed via browser using the 'edit' facility.

If the sqlite file holding usernames does not exist, it will be created as 'users.sqlite' in the working directory, with a single user 'admin' and password 'password!'. Note the exclamation mark.

Use your browser to connect to localhost:8000, follow the 'members' link, and login as admin, and by following the 'edit' link, you can add further users.

This is mainly intended to act as an example (and as a record for myself).

The htmx and css files under the static directory should be replaced with later versions of these files from the appropriate projects if they have been updated.

A number of global variables are set under weblogin/userdata.py - these can be changed if required.
