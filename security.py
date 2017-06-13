
import re
import random
import hashlib
import hmac
from secret import SECRET
from string import letters
from string import digits

import creator

# regular expressions for validating login/signup
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

invalid_username = "<b>That's not a valid username.</b><br>"
username_taken = "<b>Username already exists</b><br>"
invalid_password = "<b>That wasn't a valid password.</b><br>"
invalid_verify = "<b>Your passwords didn't match.</b><br>"
invalid_email = "<b>That's not a valid email.</b><br>"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s_%s" % (s, hash_str(s))


def check_secure_val(s):
    val = s.split('_')[0]
    if s == make_secure_val(val):
        return val


def make_salt():
    char_set = digits + letters
    return ''.join(random.sample(char_set*30, 30))


def make_pw_hash(name, pw, salt=None):
    if salt == None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt + SECRET).hexdigest()
    return '%s_%s' % (h, salt)


def valid_pw(name, pw, h):
    input_hash = make_pw_hash(name, pw, h.split("_")[1]).split("_")[0]
    existing_hash = h.split("_")[0]
    return input_hash == existing_hash

# User signup/login
def authenticate_login(username, db, User_Account_db, password=None):
    query = "SELECT * FROM User_Account_db WHERE username='%s'" % username
    hits = db.GqlQuery(query)
    if not creator.db_query_is_empty(hits):
        entry = hits[0]
    # Used by signup to check if username already exist
        if password == None:
            if entry.username == username:
                return True
            else:
                return False
    # This is used by login to authenticate
        else:
            if entry.username == username:
                if valid_pw(username, password, entry.password_hash):
                    return str(entry.key().id())
    return None


def eval_signup_or_login(username, password, verify=None,
                         email=None, username_exists=False):
    er = False
    ui_email = email or ""

    exceptions = {'username': username,
                  'email': ui_email,
                  'username_msg': '',
                  'password_msg': '',
                  'email_msg': '',
                  'verify_msg': ''}

    # used by signup to produce error if username already exists
    if username_exists:
        er = True
        exceptions['username_msg'] = username_taken

    # if login check if it is a valid username
    elif not USER_RE.match(username):
        er = True
        exceptions['username_msg'] = invalid_username
    if not PASSWORD_RE.match(password):
        er = True
        exceptions['password_msg'] = invalid_password

    # if this is a signup, verify that passwords match
    elif verify is not None and password != verify:
        er = True
        exceptions['verify_msg'] = invalid_verify

    # if this is signup, check email
    if email is not None:
        if not EMAIL_RE.match(email):
            er = True
            exceptions['email_msg'] = invalid_email

    if not er:
        return None
    return exceptions

def eval_permissions(page, entry_author_id, should_redirect=True):
    if page.user:
        if page.user.key().id() == entry_author_id:

            # permission granted
            return True
        else:

            # permission denied
            if should_redirect:
                page.redirect('/bogspot/dialog?type=not_author')
            return False
    else:
        # redirect to login
        page.redirect('/bogspot/login')
        return False