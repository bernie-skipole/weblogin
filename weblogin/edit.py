


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
    uinfo = userdata.getuserinfo(user)
    if uinfo is None:
        # user not recognised, this should never happen, but in the event it does
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    # admin and user auth levels get different templates
    if auth != "admin":
        return Template(template_name="useredit.html", context={"user": user, "fullname":uinfo.fullname})
    context = userdata.userlist(request.cookies.get('token', ''))
    if context is None:
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    # add further items to this context dictionary
    context["user"] = user
    context["fullname"] = uinfo.fullname
    return Template(template_name="adminedit.html", context=context)



@post("/fullname")
async def fullname(request: Request[str, str, State]) -> Template:
    user = request.user
    form_data = await request.form()
    newfullname = form_data.get("fullname")
    message = userdata.newfullname(user, newfullname)
    if message:
        return HTMXTemplate(None,
                        template_str=f"<p id=\"result\" class=\"w3-animate-right\" style=\"color:red\">Invalid. {message}</p>")
    # name changed
    if request.auth != "admin":
        return HTMXTemplate(None,
                        template_str="<p id=\"result\" style=\"color:green\">Success! Your full name has changed</p>")
    # Update the user list
    context = userdata.userlist(request.cookies.get('token', ''))
    if context is None:
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    return HTMXTemplate(template_name="namechanged.html", context=context)



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
    return ClientRedirect(f"/edit/deleted/{user}")


@get("/deleted/{user:str}", exclude_from_auth=True)
async def deleted(user:str) -> Template:
    "Render the deleted page"
    return Template(template_name="deleted.html", context={"user": user})


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
    # New user added, so update the user list
    context = userdata.userlist(request.cookies.get('token', ''))
    if context is None:
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    return HTMXTemplate(template_name="newuser.html", context=context)


@get("/prevpage")
async def prevpage(request: Request[str, str, State]) -> Template|ClientRedirect|Redirect:
    if request.auth != "admin":
        if 'token' in request.cookies:
            # log the user out
            userdata.logout(request.cookies['token'])
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    context = userdata.userlist(request.cookies.get('token', ''), "-")
    if context is None:
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    return Template(template_name="listusers.html", context=context)


@get("/nextpage")
async def nextpage(request: Request[str, str, State]) -> Template|ClientRedirect|Redirect:
    if request.auth != "admin":
        if 'token' in request.cookies:
            # log the user out
            userdata.logout(request.cookies['token'])
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    context = userdata.userlist(request.cookies.get('token', ''), "+")
    if context is None:
        if request.htmx:
            return ClientRedirect("/login")
        return Redirect("/login")
    return Template(template_name="listusers.html", context=context)




edit_router = Router(path="/edit", route_handlers=[edit,
                                                   fullname,
                                                   changepwd,
                                                   deluser,
                                                   deleted,
                                                   newuser,
                                                   prevpage,
                                                   nextpage
                                                  ])
