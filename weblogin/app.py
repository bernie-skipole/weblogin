from litestar import Litestar, get, post, Request
from litestar.plugins.htmx import HTMXPlugin, HTMXTemplate, ClientRedirect
from litestar.contrib.mako import MakoTemplateEngine
from litestar.template.config import TemplateConfig
from litestar.response import Template, Redirect
from litestar.static_files import create_static_files_router
from litestar.datastructures import Cookie, State

from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult, DefineMiddleware
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException

from pathlib import Path

from . import userdata

# userdata is a module defining users and password on a database,
# on first being imported if the file users.sqlite does not exist, an
# sqlite database will be created with the single user 'admin' and password 'password!'
# You should immediately log in as this user and change the password.

class LoggedInAuth(AbstractAuthenticationMiddleware):
    """Checks if a logged-in cookie is present, and verifies it
       If ok, returns an AuthenticationResult with the user, and the users
       authorisation level. If not ok raises a NotAuthorizedException"""
    async def authenticate_request(self, connection: ASGIConnection ) -> AuthenticationResult:
        # retrieve the cookie
        auth_cookie = connection.cookies
        if not auth_cookie:
            raise NotAuthorizedException()
        token =  auth_cookie.get('token')
        if not token:
            raise NotAuthorizedException()
        # the userdata.verify function looks up a dictionary of logged in users
        userauth = userdata.verify(token)
        # If not verified, userauth will be None
        # If verified userauth will be a tuple of (username, authorization level)
        # where authorization level is either 'admin' or 'user.
        if userauth is None:
            raise NotAuthorizedException()
        # Return an AuthenticationResult which will be
        # made available to route handlers as request: Request[str, str, State]
        return AuthenticationResult(user=userauth[0], auth=userauth[1])


def gotologin_error_handler(request: Request, exc: Exception) -> Redirect:
    """If a NotAuthorizedException is raised, this handles it, and redirects
       the caller to the main public page"""
    return Redirect("/")


# This defines LoggedInAuth as middleware and also
# excludes certain paths from authentication.
# In this case it excludes all routes mounted at or under `/static*`
# This allows CSS and javascript libraries to be placed there, which
# therefore do not need authentication to be accessed
auth_mw = DefineMiddleware(LoggedInAuth, exclude="static")



@get("/", exclude_from_auth=True)
async def start() -> Template:
    "This is the public root page of your site"
    return Template("landing.html")


@get("/login", exclude_from_auth=True)
async def login_page() -> Template:
    "Render the login page"
    return Template("login.html")


@post("/login", exclude_from_auth=True)
async def login(request: Request) -> Template|ClientRedirect:
    """This is a handler for the login post, in which the caller is setting their
       username and password into a form.
       Checks the user has logged in correctly, and if so creates a logged-in cookie
       for the caller and redirects the caller to /members
       which is the main private application page"""
    form_data = await request.form()
    username = form_data.get("username")
    password = form_data.get("password")
    # check these on the database of users, this call returns a logged-in cookie
    # if the user exists, and the password is correct, otherwise it returns None
    loggedincookie = await userdata.checkuserpassword(username, password)
    if loggedincookie is None:
        # unable to find a matching username/password
        # returns an 'Invalid' template which the htmx javascript
        # puts in the right place on the login page
        return HTMXTemplate(None,
                            template_str="<p id=\"result\" class=\"w3-animate-right\">Invalid</p>")
    # The user checks out ok, set redirect to the members page,
    # with the loggedincookie
    response =  ClientRedirect("/members")
    response.set_cookie(key = 'token', value=loggedincookie)
    return response


@get("/members")
async def members(request: Request[str, str, State]) -> Template:
    """The main application page, this has cookies automatically checked by
       the LoggedInAuth middleware which generates the 'request' containing
       the user and auth.
       The template returned should show your application."""
    user = request.user
    auth = request.auth
    # Return a template which will show your main application
    return Template(template_name="main.html", context={"user": user, "auth": auth})


@get("/logout")
async def logout(request: Request[str, str, State]) -> Template:
    "Logs the user out, and render the logout page"
    # log the user out
    userdata.logout(request.user)
    return Template("loggedout.html")


# Initialize the Litestar app with a Mako template engine and register the routes
app = Litestar(
    route_handlers=[start,
                    login_page,
                    login,
                    logout,
                    members,
                    create_static_files_router(path="/static", directories=["lstar/static"]),
                   ],
    exception_handlers={ NotAuthorizedException: gotologin_error_handler},
    plugins=[HTMXPlugin()],
    middleware=[auth_mw],
    template_config=TemplateConfig(directory=Path("lstar/templates"),
                                   engine=MakoTemplateEngine,
                                  ),
    )
