


from litestar import Litestar, get, post, Request, Router
from litestar.plugins.htmx import HTMXTemplate, ClientRedirect
from litestar.response import Template, Redirect
from litestar.datastructures import State


from . import userdata



@get("/")
async def edit(request: Request[str, str, State]) -> Template:
    """This allows a user to edit his/her password, or delete themself from the system
       If the user is an admin user, further facilities to add/delete/reset other users
       are available"""
    user = request.user
    auth = request.auth
    if auth != "admin":
        return Template(template_name="useredit.html", context={"user": user})
    # or if this user has admin auth
    return Template(template_name="adminedit.html", context={"user": user})


@post("/changepwd")
async def changepwd(request: Request[str, str, State]) -> Template:
    user = request.user
    form_data = await request.form()
    oldpassword = form_data.get("oldpassword")
    password1 = form_data.get("password1")
    password2 = form_data.get("password2")
    # check old password
    userinfo = userdata.checkuserpassword(user, oldpassword)
    if userinfo is None:
        # invalid old password
        return HTMXTemplate(None,
                        template_str="<p id=\"result\" class=\"w3-animate-right\" style=\"color:red\">Invalid. Incorrect old password!</p>")
    if password1 != password2:
        return HTMXTemplate(None,
                        template_str="<p id=\"result\" class=\"w3-animate-right\" style=\"color:red\">Invalid. Passwords do not match!</p>")
    message = userdata.changepassword(user, password1)
    if message:
        return HTMXTemplate(None,
                        template_str=f"<p id=\"result\" class=\"w3-animate-right\" style=\"color:red\">Invalid. {message}</p>")
    else:
        return HTMXTemplate(None,
                        template_str="<p id=\"result\" style=\"color:green\">Success! Your password has changed</p>")


@post("/deluser")
async def deluser(request: Request[str, str, State]) -> Template|ClientRedirect:
    "Deletes the user, and redirects"
    user = request.user
    message = userdata.deluser(user)
    if message:
        return HTMXTemplate(None,
                        template_str=f"Failed. {message}")
    return ClientRedirect("/")


@post("/newuser")
async def newuser(request: Request[str, str, State]) -> Template|ClientRedirect|Redirect:
    if request.auth != "admin":
        if 'token' in request.cookies:
            # log the user out
            userdata.logout(request.cookies['token'])
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    form_data = await request.form()
    username = form_data.get("username").strip()
    password = form_data.get("password").strip()
    authlevel = form_data.get("authlevel").strip().lower()
    fullname = form_data.get("fullname").strip()
    message = userdata.adduser(username, password, authlevel, fullname)
    if message:
        return HTMXTemplate(None,
                        template_str=f"<p id=\"result\" class=\"w3-animate-right\" style=\"color:red\">Invalid. {message}</p>")
    return HTMXTemplate(None,
                template_str="<p id=\"result\" style=\"color:green\">Success! New user added</p>")




edit_router = Router(path="/edit", route_handlers=[edit,
                                                   changepwd,
                                                   deluser,
                                                   newuser
                                                  ])
