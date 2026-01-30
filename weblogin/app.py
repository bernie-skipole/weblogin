"""
Creates the main litestar app with the top level routes
and authentication functions, including setting and testing cookies

Note, edit routes are set under edit.edit_router

"""

import asyncio

from pathlib import Path

from litestar import Litestar, get, post, Request
from litestar.plugins.htmx import HTMXPlugin, HTMXTemplate, ClientRedirect
from litestar.contrib.mako import MakoTemplateEngine
from litestar.template.config import TemplateConfig
from litestar.response import Template, Redirect, File
from litestar.static_files import create_static_files_router
from litestar.datastructures import Cookie, State

from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult, DefineMiddleware
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, NotFoundException

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


def gotologin_error_handler(request: Request, exc: Exception) -> ClientRedirect|Redirect:
    """If a NotAuthorizedException is raised, this handles it, and redirects
       the caller to the login page"""
    if userdata.BASEPATH:
        redirectpath = userdata.BASEPATH + "login"
    else:
        redirectpath = "/login"
    if request.htmx:
        return ClientRedirect(redirectpath)
    return Redirect(redirectpath)


def gotonotfound_error_handler(request: Request, exc: Exception) -> ClientRedirect|Redirect:
    """If a NotFoundException is raised, this handles it, and redirects
       the caller to the not found page"""
    if userdata.BASEPATH:
        redirectpath = userdata.BASEPATH + "notfound"
    else:
        redirectpath = "/notfound"
    if request.htmx:
        return ClientRedirect(redirectpath)
    return Redirect(redirectpath)


@get("/notfound", exclude_from_auth=True, sync_to_thread=False )
def notfound(request: Request) -> Template:
    "This is the not found page of your site"
    # Check if user is logged in
    loggedin = False
    cookie = request.cookies.get('token', '')
    if cookie:
        userauth = userdata.getuserauth(cookie)
        if userauth is not None:
            loggedin = True
    return Template("notfound.html", context={"loggedin":loggedin})



# Note, all routes with 'exclude_from_auth=True' do not have cookie checked
# and are not authenticated

@get("/", exclude_from_auth=True)
async def publicroot(request: Request) -> ClientRedirect|Redirect:
    "This is the public root folder of your site"
    if userdata.BASEPATH:
        redirectpath = userdata.BASEPATH + "landing"
    else:
        redirectpath = "/landing"
    if request.htmx:
        return ClientRedirect(redirectpath)
    return Redirect(redirectpath)


@get("/landing", exclude_from_auth=True)
async def landing() -> Template:
    "This is the landing page of your site"
    return Template("landing.html")


@get("/login", exclude_from_auth=True)
async def login_page() -> Template:
    "Render the login page"
    return Template("edit/login.html")


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
                            template_str="<p id=\"result\" class=\"vanish\" style=\"color:red\">Invalid</p>")
    # The user checks out ok, create a cookie for this user and set redirect to the members page,
    loggedincookie = userdata.createcookie(userinfo.user)
    # redirect with the loggedincookie
    response =  ClientRedirect("members")
    if userdata.SECURECOOKIE:
        response.set_cookie(key = 'token', value=loggedincookie, httponly=True, secure=True)
    else:
        response.set_cookie(key = 'token', value=loggedincookie, httponly=True, secure=False)
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
            return ClientRedirect("login")
        return Redirect("login")
    # Return a template which will show your main application
    return Template(template_name="members.html", context={"user": user, "auth": auth, "fullname":uinfo.fullname})


@get("/logout")
async def logout(request: Request[str, str, State]) -> Template:
    "Logs the user out, and render the logout page"
    if 'token' not in request.cookies:
        return
    # log the user out
    userdata.logout(request.cookies['token'])
    return Template("edit/loggedout.html")


@get("/getbackup/{backupfile:str}", media_type="application/octet", sync_to_thread=False )
def getbackup(backupfile:str, request: Request[str, str, State]) -> File:
    "Download a backup file to the browser client"
    auth = request.auth
    if auth != "admin":
        raise NotAuthorizedException()
    if backupfile.startswith("."):
        raise NotFoundException()
    backupfolder = userdata.USERDBASE_LOCATION
    if not backupfolder:
        raise NotFoundException()
    if backupfile == userdata.USERDBASE.name:
        # do not allow download of current database
        raise NotFoundException()
    if not backupfile.endswith(".sqlite"):
        raise NotFoundException()
    backuppath = backupfolder / backupfile
    if not backuppath.is_file():
        raise NotFoundException()
    return File(
        path=backuppath,
        filename=backupfile
        )


# This defines LoggedInAuth as middleware and also
# excludes certain paths from authentication.
# In this case it excludes all routes mounted at or under `/static*`
# This allows CSS and javascript libraries to be placed there, which
# therefore do not need authentication to be accessed
auth_mw = DefineMiddleware(LoggedInAuth, exclude="static")


# Initialize the Litestar app with a Mako template engine and register the routes
app = Litestar( path = userdata.BASEPATH,
    route_handlers=[publicroot,
                    landing,
                    notfound,
                    login_page,
                    login,
                    logout,
                    getbackup,
                    edit.edit_router,     # This router in edit.py deals with routes below /edit
                    members,
                    create_static_files_router(path="/static", directories=[STATICFILES]),
                   ],
    exception_handlers={ NotAuthorizedException: gotologin_error_handler, NotFoundException: gotonotfound_error_handler},
    plugins=[HTMXPlugin()],
    middleware=[auth_mw],
    template_config=TemplateConfig(directory=TEMPLATEFILES,
                                   engine=MakoTemplateEngine,
                                  ),
    )
