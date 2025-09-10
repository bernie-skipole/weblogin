"""This module defines users and password on a database,
   on first being imported if the file users.sqlite does not exist, an
   sqlite database will be created with the single user 'admin' and password 'password!'
   You should immediately log in as this user and change the password.
   """

import sqlite3, os, time, re

from hashlib import scrypt

from secrets import token_urlsafe

from pathlib import Path

from dataclasses import dataclass


# set the location of sqlite database as the current working directory
# this database will hold users and their hashed passwords
USERDBASE = Path.cwd() / "users.sqlite"


# Dictionary of randomstring:userauth, built as cookies are created
# The randomstring is sent as the cookie token
USERCOOKIES = {}

# seconds after which an idle user will be logged out (5 minutes in this example)
IDLETIMEOUT = 300


@dataclass
class UserAuth():
    "Class used to hold a logged in user details"
    user:str
    auth:str
    time:float



if not USERDBASE.is_file():
    # create a database file, initially with user 'admin', password 'password!', and auth 'admin'
    # where auth is either 'admin' or 'user'. passwords are stored as scrypt hashes

    # generate and store a random number as salt
    salt = os.urandom(16)

    # encode the userpassword
    encoded_password = scrypt( password = 'password!'.encode(),
                               salt = salt,
                               n = 2048,
                               r = 8,
                               p = 1,
                               maxmem=0,
                               dklen=64)

    con = sqlite3.connect(USERDBASE)

    with con:
        con.execute("CREATE TABLE users(name VARCHAR UNIQUE, password, auth, salt)")
        con.execute("INSERT INTO users VALUES(:name, :password, :auth, :salt)",
              {'name':'admin', 'password':encoded_password, 'auth':'admin', 'salt':salt})
    con.close()



def checkuserpassword(user:str, password:str) -> UserAuth|None:
    """Given a user,password pair from a login form,
       If this matches the database entry for the user, return a UserAuth object
       If this user does not exist, or the password does not match, return None"""
    # everytime a user logs in, expired cookies are deleted
    cleanusercookies()
    if (not user) or (not password):
        return
    if len(user)<5:
        return
    if len(password)<8:
        return
    con = sqlite3.connect(USERDBASE)
    cur = con.cursor()
    cur.execute("SELECT password,auth,salt FROM users WHERE name = ?", (user,))
    result = cur.fetchone()
    cur.close()
    con.close()
    if not result:
        return
    # encode the received password, and compare it with the value in the database
    storedpassword, auth, salt = result
    # hash the received password to compare it with the encoded password
    receivedpassword = scrypt( password = password.encode(),
                               salt = salt,
                               n = 2048,
                               r = 8,
                               p = 1,
                               maxmem=0,
                               dklen=64)
    if receivedpassword == storedpassword:
        # user and password are ok, return a UserAuth object
        return UserAuth(user, auth, time.time())
    # invalid password, return None


def getcookie(userauth:UserAuth) -> str:
    "Given a userauth object, return a cookie string value"
    randomstring = token_urlsafe(16)
    userauth.time = time.time()
    # record this logged in user in a loggedin dictionary
    USERCOOKIES[randomstring] = userauth
    # The cookie returned will be the random string
    return randomstring


def cleanusercookies() -> None:
    "Every time someone logs in, remove any expired cookies from USERCOOKIES"
    now = time.time()
    for cookie in list(USERCOOKIES.keys()):
        userauth = USERCOOKIES[cookie]
        if now-userauth.time > IDLETIMEOUT:
            # log the user out, after IDLETIMEOUT inactivity
            del USERCOOKIES[cookie]


def verify(cookie:str) -> UserAuth|None:
    "Return UserAuth object, or None on failure"
    if cookie not in USERCOOKIES:
        return
    userauth = USERCOOKIES[cookie]
    now = time.time()
    if now-userauth.time > IDLETIMEOUT:
        # log the user out, as IDLETIMEOUT inactivity has passed
        del USERCOOKIES[cookie]
        return
    # success, update the time
    userauth.time = now
    return userauth


def logout(user:str) -> None:
    "Logs the user out"
    for cookie in list(USERCOOKIES.keys()):
        userauth = USERCOOKIES[cookie]
        if user == userauth.user:
            del USERCOOKIES[cookie]


def changepassword(user:str, newpassword:str) -> str|None:
    "Sets a new password for the user, on success returns None, on failure returns an error message"

    if len(newpassword) < 8:
        return "New password needs at least 8 characters"

    if re.search('[^a-zA-Z0-9]', newpassword) is None:
        return "New password needs at least one special character"

    # generate and store a random number as salt
    salt = os.urandom(16)

    # encode the userpassword
    encoded_password = scrypt( password = newpassword.encode(),
                               salt = salt,
                               n = 2048,
                               r = 8,
                               p = 1,
                               maxmem=0,
                               dklen=64)

    con = sqlite3.connect(USERDBASE)
    with con:
        cur = con.cursor()
        cur.execute("SELECT count(*) FROM users WHERE name = ?", (user,))
        result = cur.fetchone()[0]
        if result:
            cur.execute("UPDATE users SET password = ?, salt = ? WHERE name = ?", (encoded_password, salt, user))
    cur.close()
    con.close()
    if not result:
        # invalid user
        logout(user)
        return "User not found"


def deluser(user:str) -> str|None:
    "Deletes the user, on success returns None, on failure returns an error message"
    if not user:
        return "No user given"
    con = sqlite3.connect(USERDBASE)
    cur = con.cursor()
    cur.execute("SELECT auth FROM users WHERE name = ?", (user,))
    result = cur.fetchone()
    if not result:
        cur.close()
        con.close()
        return "User not recognised"
    if result[0] == "admin":
        # Further check: confirm this is not the only admin
        cur.execute("SELECT count(*) FROM users WHERE auth = 'admin'")
        number = cur.fetchone()[0]
        if number == 1:
            cur.close()
            con.close()
            return "Cannot delete the only administrator"
    curs.execute("DELETE FROM users WHERE name = ?", (user,))
    con.commit()
    cur.close()
    con.close()
    # The user is deleted


def adduser(user:str, password:str, auth:str) -> str|None:
    "Checks the user does not already exist, returns None on success, on failure returns an error message"
    if not user:
        return "No user given"
    elif len(password) < 8:
        return "New password needs at least 8 characters"
    elif re.search('[^a-zA-Z0-9]', password) is None:
        return "The password needs at least one special character"
    elif auth != "user" and auth != "admin":
        return "Auth level not recognised"
