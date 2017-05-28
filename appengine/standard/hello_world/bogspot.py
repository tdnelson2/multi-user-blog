import os
import re
import random
import hashlib
import hmac
from secret import SECRET
from string import letters
from string import digits

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

invalid_username = "<b>That's not a valid username.</b>"
username_taken = "<b>Username already exists</b>"
invalid_password = "<b>That wasn't a valid password.</b>"
invalid_verify = "<b>Your passwords didn't match.</b>"
invalid_email = "<b>That's not a valid email.</b>"

##### User security
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(s):
    val = s.split('|')[0]
    if s == make_secure_val(val):
        return val

def make_salt():
    char_set = digits + letters
    return ''.join(random.sample(char_set*30, 30))


def make_pw_hash(name, pw, salt=None):
    if salt == None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt + SECRET).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    input_hash = make_pw_hash(name, pw, h.split("|")[1]).split("|")[0]
    existing_hash = h.split("|")[0]
    return input_hash == existing_hash

##### User signup/login
def authenticate_login(username, password = None):
    query = "SELECT * FROM User_Account_db WHERE username='%s'" % username
    hits = db.GqlQuery(query)
    username_match = None
    password_match = None
    user_id = None
    entry = None
    for e in hits:
        username_match = e.username
        password_hash = e.password_hash
        entry = e
        break

    # This can be used by signup to check if username already exist
    if password == None:
        if username_match == username:
            return True
        else:
            return None

    # This is used by login to authenticate
    else:
        if username_match == username:
            if valid_pw(username, password, password_hash):
                return str(entry.key().id())
    return None

def eval_signup_or_login(username, password, verify = None,
                         email = None, username_exists = False):
    er = False

    exceptions = {'username':'',
                  'email':'',
                  'username_msg':'',
                  'password_msg':'',
                  'email_msg':'',
                  'verify_msg':''}

    # used by signup to produce error if username already exists
    if username_exists:
        er = True
        exceptions['username_msg'] = username_taken
        exceptions['username'] = username

    # otherwise just check if it is a valid username
    elif not USER_RE.match(username):
        er = True
        exceptions['username_msg'] = invalid_username
        exceptions['username'] = username
    if not PASSWORD_RE.match(password):
        er = True
        exceptions['password_msg'] = invalid_password

    # if this is a signup, verify that passwords match
    elif verify is not None and password != verify:
        er = True
        exceptions['verify_msg'] = invalid_verify

    # check email if this is signup
    if email is not None:
        if email != "" and not EMAIL_RE.match(email):
            er = True
            exceptions['email_msg'] = invalid_email
            exceptions['email'] = email

    if not er:
        return None
    return exceptions

##### Databases
class Blog_db(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class User_Account_db(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

##### Page handlers
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_username_from_cookie(self, cookie_name):
        user_cookie_str = self.request.cookies.get(cookie_name)
        if user_cookie_str:
            cookie_val = check_secure_val(user_cookie_str)
            if cookie_val:
                entry = User_Account_db.get_by_id(int(cookie_val))
                if not entry == None:
                    return entry.username
        return None

    def write_login_cookie(self, user_id):
        current_user_s = make_secure_val(user_id)
        self.response.headers.add_header('Set-Cookie',
                                          str('CurrentUser=%s; Path=/bogspot/'
                                               % current_user_s))

    # def initialize(self, *a, **kw):
    #     webapp2.RequestHandler.initialize(self, *a, **kw)
    #     uid = self.read_secure_cookie('user_id')
    #     self.user = uid and User_Account_db.by_id(int(uid))

class SignupHandler(Handler):
    def get(self):
        current_user = self.get_username_from_cookie('CurrentUser')
        if current_user:
            self.redirect('/bogspot/welcome')
        else:
            self.render('signup.html')

    def post(self):
        username = self.request.get('username', 0)
        password = self.request.get('password', 0)
        verify = self.request.get('verify', 0)
        email = self.request.get('email', 0)
        username_exists = authenticate_login(username)
        params = eval_signup_or_login(username, password, verify, email, username_exists)
        if params is None:
            salt = make_salt()
            password_hash = make_pw_hash(username, password, salt)
            row = User_Account_db(username = username, password_hash = password_hash, email = email, salt = salt)
            row.put()
            self.write_login_cookie(str(row.key().id()))
            self.redirect('/bogspot/welcome')
        else:
            self.render('signup.html',  **params)

class LoginHandler(Handler):
    def get(self):
        current_user = self.get_username_from_cookie('CurrentUser')
        if current_user:
            self.redirect('/bogspot/welcome')
        else:
            self.render('login.html')
    def post(self):
        username = self.request.get('username', 0)
        password = self.request.get('password', 0)
        params = eval_signup_or_login(username, password)
        if params is None:
            user_id = authenticate_login(username, password)
            if user_id:
                self.write_login_cookie(user_id)
                self.redirect('/bogspot/welcome')
            else:
                self.render('login.html',  login_msg="<b>Invalid login</b>")
        else:
            self.render('login.html', **params)

class WelcomeHandler(Handler):
    def get(self):
        current_user = self.get_username_from_cookie('CurrentUser')
        if current_user:
            self.render('welcome.html', username = current_user)
        else:
            self.redirect('/bogspot/signup')

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         str('CurrentUser=; Path=/bogspot/'))
        self.redirect("/bogspot/login")

class MainPageHandler(Handler):
    def render_front(self):
        entries = db.GqlQuery("select * from Blog_db order by created desc")
        self.render("main.html", entries = entries)

    def get(self):
        self.render_front()

class NewPostHandler(Handler):
    def render_form(self, error=""):
        self.render("new-post.html", error=error)

    def get(self):
        self.render_form()

    def post(self):
        title = self.request.get("subject")
        body = self.request.get("content")

        if title and body:
            row = Blog_db(title = title, body = body)
            row.put()
            print(row.key().id())
            self.redirect("/bogspot/" + str(row.key().id()))

        else:
            error = "We need both title and a body!"
            self.render_form(error)

class SpecificPostHandler(Handler):
    def get(self, entry_id):
        entry = Blog_db.get_by_id(int(entry_id))
        if entry:
            self.render("new-blog-entry.html", title = entry.title, body = entry.body)
        else:
            self.write("could not render page for entry id: " + entry_id)

app = webapp2.WSGIApplication([(r'/bogspot/signup', SignupHandler),
                               (r'/bogspot/login', LoginHandler),
                               (r'/bogspot/logout', LogoutHandler),
                               (r'/bogspot/welcome', WelcomeHandler),
                               (r'/bogspot', MainPageHandler),
                               (r'/bogspot/NewPostHandler', NewPostHandler),
                               (r'/bogspot/(\d+)', SpecificPostHandler)],
                               debug = True)

