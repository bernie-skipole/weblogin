"""This module defines users and password on a database,
   on first being imported if the file users.sqlite does not exist, an
   sqlite database will be created with the single user 'admin' and password 'password!'
   You should immediately log in as this user and change the password.
   """

import sqlite3, os, time, asyncio

from hashlib import scrypt

from secrets import token_urlsafe

from pathlib import Path


# location of sqlite database where users are kept
USERDBASE = Path(__file__).parent.resolve() / "users.sqlite"


# Dictionary of randomstring:(time, username, auth), built as cookies are created
# The randomstring is sent as the cookie token
USERCOOKIES = {}

# seconds after which an idle user will be logged out (5 minutes in this example)
IDLETIMEOUT = 300



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
        con.execute("CREATE TABLE users(name, password, auth, salt)")
        con.execute("INSERT INTO users VALUES(:name, :password, :auth, :salt)",
              {'name':'admin', 'password':encoded_password, 'auth':'admin', 'salt':salt})
    con.close()



async def checkuserpassword(user:str, password:str) -> str|None:
    """Given a user,password pair from a login form, return a 'logged in' cookie
       if this matches the database entry for the user.
       If this user does not exist, or the password does not match, return None"""
    # everytime a user logs in, expired cookies are deleted
    cleanusercookies()
    if (not user) or (not password):
        # sleep to force a time delay to annoy anyone trying to guess a password
        await asyncio.sleep(1.0)
        return
    if len(user)<5:
        await asyncio.sleep(1.0)
        return
    if len(password)<8:
        await asyncio.sleep(1.0)
        return
    con = sqlite3.connect(USERDBASE)
    cur = con.cursor()
    cur.execute("SELECT password,auth,salt FROM users WHERE name = ?", (user,))
    result = cur.fetchone()
    cur.close()
    con.close()
    if not result:
        await asyncio.sleep(1.0)
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
    if receivedpassword != storedpassword:
        # invalid password
        await asyncio.sleep(1.0)
        return
    # user is logging in, return a cookie
    randomstring = token_urlsafe(16)
    # record this logged in user in a loggedin dictionary
    USERCOOKIES[randomstring] = (time.time(), user, auth)
    # The cookie returned will be the random string
    return randomstring


def cleanusercookies() -> None:
    "Every time someone logs in, remove any expired cookies from USERCOOKIES"
    now = time.time()
    for cookie in list(USERCOOKIES.keys()):
        t, user, auth = USERCOOKIES[cookie]
        if now-t > IDLETIMEOUT:
            # log the user out, after IDLETIMEOUT inactivity
            del USERCOOKIES[cookie]


def verify(cookie:str) -> tuple[str, str]|None:
    "Return (username, auth), or None on failure"
    if cookie not in USERCOOKIES:
        return
    t, user, auth = USERCOOKIES[cookie]
    now = time.time()
    if now-t > IDLETIMEOUT:
        # log the user out, as IDLETIMEOUT inactivity has passed
        del USERCOOKIES[cookie]
        return
    # success, update the time
    USERCOOKIES[cookie] = (now, user, auth)
    return user, auth


def logout(user:str) -> None:
    "Logs the user out"
    for cookie in list(USERCOOKIES.keys()):
        t, loggedinuser, auth = USERCOOKIES[cookie]
        if user == loggedinuser:
            del USERCOOKIES[cookie]
