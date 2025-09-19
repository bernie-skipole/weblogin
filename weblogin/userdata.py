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

from functools import lru_cache


# set the location of sqlite database as the current working directory
# this database will hold users and their hashed passwords
USERDBASE = Path.cwd() / "users.sqlite"


# Dictionary of randomstring:userauth, built as cookies are created
# The randomstring is sent as the cookie token
USERCOOKIES = {}

# seconds after which an idle user will be logged out (5 minutes in this example)
IDLETIMEOUT = 300


@dataclass
class UserInfo():
    "Class used to hold user details"
    user:str
    auth:str
    fullname:str


@dataclass
class UserAuth():
    "Class used to hold a logged in user details"
    user:str
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
        con.execute("CREATE TABLE users(name TEXT PRIMARY KEY, password TEXT NOT NULL, auth TEXT NOT NULL, salt TEXT NOT NULL, fullname TEXT) WITHOUT ROWID")
        con.execute("INSERT INTO users VALUES(:name, :password, :auth, :salt, :fullname)",
              {'name':'admin', 'password':encoded_password, 'auth':'admin', 'salt':salt, 'fullname':'Default Administrator'})
    con.close()



def checkuserpassword(user:str, password:str) -> UserInfo|None:
    """Given a user,password pair from a login form,
       If this matches the database entry for the user, return a UserInfo object
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
    cur.execute("SELECT password,auth,salt,fullname FROM users WHERE name = ?", (user,))
    result = cur.fetchone()
    cur.close()
    con.close()
    if not result:
        return
    # encode the received password, and compare it with the value in the database
    storedpassword, auth, salt, fullname = result
    # hash the received password to compare it with the encoded password
    receivedpassword = scrypt( password = password.encode(),
                               salt = salt,
                               n = 2048,
                               r = 8,
                               p = 1,
                               maxmem=0,
                               dklen=64)
    if receivedpassword == storedpassword:
        # user and password are ok, return a UserInfo object
        return UserInfo(user, auth, fullname)
    # invalid password, return None


def getcookie(user:str) -> str:
    """Given a user, return a cookie string value
       Also sets a UserAuth object into USERCOOKIES"""
    randomstring = token_urlsafe(16)
    userauth = UserAuth(user,time.time())
    # record this logged in user in a loggedin dictionary
    USERCOOKIES[randomstring] = userauth
    # The cookie returned will be the random string
    return randomstring


@lru_cache
def getuserinfo(user:str) -> UserInfo:
    "Return UserInfo object for the given user, if not found, return None"

    # Note this is cached, so repeated calls for the same user
    # do not need sqlite lookups.

    con = sqlite3.connect(USERDBASE)
    cur = con.cursor()
    cur.execute("SELECT auth, fullname FROM users WHERE name = ?", (user,))
    result = cur.fetchone()
    cur.close()
    con.close()
    if not result:
        return
    auth, fullname = result
    return UserInfo(user, auth, fullname)


def cleanusercookies() -> None:
    "Every time someone logs in, remove any expired cookies from USERCOOKIES"
    now = time.time()
    for cookie in list(USERCOOKIES.keys()):
        userauth = USERCOOKIES[cookie]
        if now-userauth.time > IDLETIMEOUT:
            # log the user out, after IDLETIMEOUT inactivity
            del USERCOOKIES[cookie]


def verify(cookie:str) -> UserInfo|None:
    "Return UserInfo object, or None on failure"
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
    # return a UserInfo object
    return getuserinfo(userauth.user)


def logoutuser(user:str) -> None:
    "Logs the user out, even if user has multiple sessions open"
    for cookie in list(USERCOOKIES.keys()):
        userauth = USERCOOKIES[cookie]
        if user == userauth.user:
            del USERCOOKIES[cookie]


def logout(cookie:str) -> None:
    "Logout function by removing cookie from dictionary of logged in cookies"
    if cookie not in USERCOOKIES:
        return
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
        logoutuser(user)
        return "User not found"


def deluser(user:str) -> str|None:
    "Deletes the user, on success returns None, on failure returns an error message"
    if not user:
        return "No user given"
    # log the user out
    logoutuser(user)
    # clear cache
    getuserinfo.cache_clear()
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
