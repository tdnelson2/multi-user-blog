import re
import random
import hashlib
import hmac
from secret import SECRET
from string import letters
from string import digits

import creator


class Utils():

    """ methods for securing and validating """

    @classmethod
    def hash_str(self, s):
        return hmac.new(SECRET, s).hexdigest()

    @classmethod
    def make_secure_val(self, s):
        return "%s_%s" % (s, self.hash_str(s))

    @classmethod
    def check_secure_val(self, s):
        val = s.split('_')[0]
        if s == self.make_secure_val(val):
            return val

    @classmethod
    def make_salt(self):
        char_set = digits + letters
        return ''.join(random.sample(char_set*30, 30))

    @classmethod
    def make_pw_hash(self, name, pw, salt=None):
        if salt == None:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt + SECRET).hexdigest()
        return '%s_%s' % (h, salt)

    @classmethod
    def valid_pw(self, name, pw, h):
        input_hash = self.make_pw_hash(name, pw, h.split("_")[1]).split("_")[0]
        existing_hash = h.split("_")[0]
        return input_hash == existing_hash

# User signup/login


def authenticate_login(username, db, UserAccounts, password=None):
    """ authenticates new or existing users """

    query = "SELECT * FROM UserAccounts WHERE username='%s'" % username
    hits = db.GqlQuery(query)
    if not creator.db_query_is_empty(hits):
        entry = hits[0]
        # Used by signup to check if username already exist
        if password == None:
            return entry.username == username
        # Used by login to authenticate
        else:
            if entry.username == username:
                if Utils.valid_pw(username, password, entry.password_hash):
                    return str(entry.key().id())
    return None


def eval_signup_or_login(username, password, verify=None,
                         email=None, username_exists=False):
    """ checks whether login or signup information is valid """

    # regular expressions for validating login/signup
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    invalid_username = "<b>That's not a valid username.</b><br>"
    username_taken = "<b>Username already exists</b><br>"
    invalid_password = "<b>That wasn't a valid password.</b><br>"
    invalid_verify = "<b>Your passwords didn't match.</b><br>"
    invalid_email = "<b>That's not a valid email.</b><br>"

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


def eval_authorization(page, entry_author_id, should_redirect=True):
    """ checks whether current user owns any given user-generated item
    and redirects to a warning page if authorization is not granted """

    if page.user.key().id() == entry_author_id:

        # permission granted
        return True
    else:

        # permission denied
        if should_redirect:
            page.redirect('/bogspot/dialog?type=not_author')
        return False
