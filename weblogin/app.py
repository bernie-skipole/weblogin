
import asyncio

from pathlib import Path

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

from . import userdata, edit

# userdata is a module defining users and password on a database,
# on first being imported if the file users.sqlite does not exist, an
# sqlite database will be created with the single user 'admin' and password 'password!'
# You should immediately log in as this user and change the password.



# location of static files, for CSS and javascript
STATICFILES = Path(__file__).parent.resolve() / "static"

# location of template files
TEMPLATEFILES = Path(__file__).parent.resolve() / "templates"


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
        userinfo = userdata.verify(token)
        # If not verified, userinfo will be None
        # If verified userinfo will be a userdata.UserInfo object
        if userinfo is None:
            raise NotAuthorizedException()
        # Return an AuthenticationResult which will be
        # made available to route handlers as request: Request[str, str, State]
        return AuthenticationResult(user=userinfo.user, auth=userinfo.auth)


def gotologin_error_handler(request: Request, exc: Exception) -> Redirect:
    """If a NotAuthorizedException is raised, this handles it, and redirects
       the caller to the login page"""
    if request.htmx:
        return ClientRedirect("/login")
    return Redirect("/login")


# This defines LoggedInAuth as middleware and also
# excludes certain paths from authentication.
# In this case it excludes all routes mounted at or under `/static*`
# This allows CSS and javascript libraries to be placed there, which
# therefore do not need authentication to be accessed
auth_mw = DefineMiddleware(LoggedInAuth, exclude="static")


# Note, all routes with 'exclude_from_auth=True' do not have cookie checked
# and are not authenticated

@get("/", exclude_from_auth=True)
async def publicroot() -> Template:
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
    # check these on the database of users, this checkuserpassword returns a userdata.UserInfo object
    # if the user exists, and the password is correct, otherwise it returns None
    userinfo = userdata.checkuserpassword(username, password)
    if userinfo is None:
        # sleep to force a time delay to annoy anyone trying to guess a password
        await asyncio.sleep(1.0)
        # unable to find a matching username/password
        # returns an 'Invalid' template which the htmx javascript
        # puts in the right place on the login page
        return HTMXTemplate(None,
                            template_str="<p id=\"result\" class=\"w3-animate-right\" style=\"color:red\">Invalid</p>")
    # The user checks out ok, create a cookie for this user and set redirect to the members page,
    loggedincookie = userdata.getcookie(userinfo.user)
    # redirect with the loggedincookie
    response =  ClientRedirect("/members")
    response.set_cookie(key = 'token', value=loggedincookie)
    return response



@get("/members")
async def members(request: Request[str, str, State]) -> Template|ClientRedirect|Redirect:
    """The main members application page, this has cookies automatically checked by
       the LoggedInAuth middleware which generates the 'request' containing
       the user and auth.
       The template returned should show your application."""
    user = request.user
    auth = request.auth
    uinfo = userdata.getuserinfo(user)
    if uinfo is None:
        # user not recognised, this should never happen, but in the event it does
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    # Return a template which will show your main application
    return Template(template_name="members.html", context={"user": user, "auth": auth, "fullname":uinfo.fullname})


@get("/logout")
async def logout(request: Request[str, str, State]) -> Template:
    "Logs the user out, and render the logout page"
    # log the user out
    userdata.logout(request.user)
    return Template("loggedout.html")


# Initialize the Litestar app with a Mako template engine and register the routes
app = Litestar(
    route_handlers=[publicroot,
                    login_page,
                    login,
                    logout,
                    edit.edit_router,     # This router in edit.py deals with routes below /edit
                    members,
                    create_static_files_router(path="/static", directories=[STATICFILES]),
                   ],
    exception_handlers={ NotAuthorizedException: gotologin_error_handler},
    plugins=[HTMXPlugin()],
    middleware=[auth_mw],
    template_config=TemplateConfig(directory=Path(TEMPLATEFILES),
                                   engine=MakoTemplateEngine,
                                  ),
    )
