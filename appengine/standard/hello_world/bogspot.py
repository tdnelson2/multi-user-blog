import os
import re
import random
import hashlib
import hmac
from secret import SECRET
from string import letters
from string import digits
# from markdown import *
# http://pythonhosted.org/Markdown/install.html
# https://pythonhosted.org/Markdown/reference.html

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

# invalid_username = "<div class=\"error\"><b>That's not a valid username.</b></div>"
# username_taken = "<div class=\"error\"><b>Username already exists</b></div>"
# invalid_password = "<div class=\"error\"><b>That wasn't a valid password.</b></div>"
# invalid_verify = "<div class=\"error\"><b>Your passwords didn't match.</b></div>"
# invalid_email = "<div class=\"error\"><b>That's not a valid email.</b></div>"
invalid_username = "<b>That's not a valid username.</b><br>"
username_taken = "<b>Username already exists</b><br>"
invalid_password = "<b>That wasn't a valid password.</b><br>"
invalid_verify = "<b>Your passwords didn't match.</b><br>"
invalid_email = "<b>That's not a valid email.</b><br>"

##### User security
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
                  'verify_msg':'',
                  'login_toggle_link':'/bogspot/login',
                  'login_toggle_text':'Login'}

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
        if not EMAIL_RE.match(email):
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
    author_id = db.IntegerProperty(required = True)
    likes = db.ListProperty(int)


class User_Account_db(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

def db_query_is_empty(result):
    try:
        r = result[0]
        return False
    except IndexError:
        return True

def all_posts():
    posts = db.GqlQuery("SELECT * FROM Blog_db ORDER BY created DESC")
    # test if anything was returned
    if not db_query_is_empty(posts):
        return posts
    return None
    # try:
    #     r = posts[0]
    #     if r:
    #         return posts
    # except IndexError:
    #     return None

##### Page handlers
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_user_account(self, cookie_name):
        user_cookie_str = self.request.cookies.get(cookie_name)
        if user_cookie_str:
            cookie_val = check_secure_val(user_cookie_str)
            if cookie_val:
                entry = User_Account_db.get_by_id(int(cookie_val))
                try:
                    un = entry.username
                    return entry
                except AttributeError:
                    return None
        return None


    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def write_login_cookie(self, user_id):
        current_user_s = make_secure_val(user_id)
        self.response.headers.add_header('Set-Cookie',
                                          str('CurrentUser=%s; Path=/bogspot/'
                                               % current_user_s))

    def eval_permissions(self, entry_author_id, should_redirect=True):
        if self.user:
            if self.user.key().id() == entry_author_id:
                # permission granted
                return True
            else:
                # permission denied
                if should_redirect:
                    self.redirect('/bogspot/error?type=not_author')
                return False
        else:
            # redirect to login
            self.redirect('/bogspot/login')
            return False

    def is_liked(self, entry):
        if self.user:
            likes = entry.likes
            user_id = self.user.key().id()
            if user_id in likes:
                return True
        return False

    def toggle_login(self):
        if self.user:
            return ["/bogspot/logout", "Log Out"]
        else:
            return ["/bogspot/login", "Sign In"]

    def render_new_post_form(self, error="", title="", body="", cancel_button_link="/bogspot"):
        params = self.toggle_login()
        self.render("new-post.html", error=error, title=title, body=body, cancel_button_link=cancel_button_link, login_toggle_link=params[0], login_toggle_text=params[1])

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.user = self.get_user_account('CurrentUser')

class SignupHandler(Handler):
    def get(self):
        current_user = self.get_user_account('CurrentUser')
        if current_user:
            self.redirect('/bogspot/welcome')
        else:
            self.render('signup.html', login_toggle_link='/bogspot/login', login_toggle_text='Login')

    def post(self):
        username = self.request.get('username', "")
        password = self.request.get('password', "")
        verify = self.request.get('verify', "")
        email = self.request.get('email', "")
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
    def append_signup_parms(self, params):
        params['login_toggle_link'] = '/bogspot/signup'
        params['login_toggle_text'] = 'Create Account'
        return params

    def get(self):
        current_user = self.get_user_account('CurrentUser')
        if current_user:
            self.redirect('/bogspot/welcome')
        else:
            self.render('login.html', login_toggle_link='/bogspot/signup', login_toggle_text='Create Account')
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
                self.render('login.html',  login_msg="<br><b>Invalid login</b>", login_toggle_link='/bogspot/signup', login_toggle_text='Create Account')
        else:
            params = self.append_signup_parms(params)
            self.render('login.html', **params)

class WelcomeHandler(Handler):
    def get(self):
        current_user = self.get_user_account('CurrentUser')
        if current_user:
            self.render('welcome.html', username = current_user.username, login_toggle_link='/bogspot/logout', login_toggle_text='Logout')
        else:
            self.redirect('/bogspot/signup')

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         str('CurrentUser=; Path=/bogspot/'))
        self.redirect("/bogspot/login")

class MainPageHandler(Handler):
    def render_front(self):
        # entries = db.GqlQuery("select * from Blog_db order by created desc")
        entries = all_posts()
        parms = self.toggle_login()
        self.render("main.html", entries = entries, login_toggle_link=parms[0], login_toggle_text=parms[1], user = self.user)

    def get(self):
        self.render_front()

class MainRedirectHandler(Handler):
    def get(self):
        self.redirect("/bogspot/index")

class NewPostHandler(Handler):
    def get(self):
        self.render_new_post_form()

    def post(self):
        title = self.request.get("subject")
        body = self.request.get("content")

        if title and body:
            row = Blog_db(title = title, body = body, author_id = self.user.key().id())
            row.put()
            self.redirect("/bogspot/" + str(row.key().id()))
        else:
            self.render_new_post_form(error = "We need both title and a body!", title=title, body=body)

class SpecificPostHandler(Handler):
    def get(self, entry_id):
        entry = Blog_db.get_by_id(int(entry_id))
        if entry:
            liked = "disabled"
            if self.is_liked(entry):
                liked = "enabled"
            parms = self.toggle_login()
            self.render("new-blog-entry.html", entry = entry, user = self.user, like_status = liked, login_toggle_link=parms[0], login_toggle_text=parms[1])
        else:
            self.write("could not render page for entry id: " + entry_id)
    def post(self, entry_id):
        # http://fontawesome.io/
        # self.write(self)
        entry = Blog_db.get_by_id(int(entry_id))
        if self.request.get("edit"):
            if self.eval_permissions(entry.author_id):
                entry_id_hash = make_secure_val(entry_id)
                self.redirect('/bogspot/edit/%s' % entry_id_hash)
        elif self.request.get("delete"):
            if self.eval_permissions(entry.author_id):
                entry.delete()
                self.redirect('/bogspot/deleted')
        elif self.request.get("like"):
            if self.eval_permissions(entry.author_id, False):
                # can't like your own post
                self.redirect('/bogspot/error?type=like')
            else:
                parms = self.toggle_login()
                if self.user:
                    if self.is_liked(entry):
                        # already liked, unklike
                        entry.likes.remove(self.user.key().id())
                        entry.put()
                        self.redirect("/bogspot/%s" % str(entry.key().id()))
                    else:
                        # like
                        entry.likes.append(self.user.key().id())
                        entry.put()
                        self.redirect("/bogspot/%s" % str(entry.key().id()))
                else:
                    self.redirect('/bogspot/login')


class EditPostHandler(Handler):
    def get(self, entry_id_hash):
        entry_id = check_secure_val(entry_id_hash)
        if entry_id:
            entry = Blog_db.get_by_id(int(entry_id))
            if entry.author_id == self.user.key().id():
                params = self.toggle_login()
                self.render_new_post_form(title = entry.title, body = entry.body, cancel_button_link = "/bogspot/%s" % entry_id)
            else:
                self.write("You are not allowed to edit this post")
        else:
            self.write("The URL for this entry has been tampered with")
    def post(self, entry_id_hash):
        title = self.request.get("subject")
        body = self.request.get("content")
        entry_id = check_secure_val(entry_id_hash)
        if title and body:
            if entry_id:
                entry = Blog_db.get_by_id(int(entry_id))
                entry.title = title
                entry.body = body
                entry.put()
                self.redirect("/bogspot/" + str(entry.key().id()))
            else:
                self.write("Somehow you were almost able to post this without correct permisions")
        else:
            self.render_new_post_form(error = "We need both title and a body!", title=title, body=body, cancel_button_link = "/bogspot/%s" % entry_id)

class EditPermissionDeniedHandler(Handler):
    def get(self):
        type = self.request.get('type')
        if type == 'not_author':
            self.render('error.html', msg="You are not authorized to modify this post!")
        elif type == 'like':
            self.render('error.html', msg="You can't like your own post. That's just silly.")

class PostDeletedHandler(Handler):
    def get(self):
        self.render('error.html', msg="Post has been deleted")






app = webapp2.WSGIApplication([(r'/bogspot/signup', SignupHandler),
                               (r'/bogspot/login', LoginHandler),
                               (r'/bogspot/logout', LogoutHandler),
                               (r'/bogspot/welcome', WelcomeHandler),
                               (r'/bogspot/index', MainPageHandler),
                               (r'/bogspot/newpost', NewPostHandler),
                               (r'/bogspot/(\d+)', SpecificPostHandler),
                               (r'/bogspot/edit/(\w+)', EditPostHandler),
                               (r'/bogspot/error', EditPermissionDeniedHandler),
                               (r'/bogspot/deleted', PostDeletedHandler),
                               (r'/bogspot/', MainRedirectHandler),
                               (r'/bogspot', MainRedirectHandler)],
                               debug = True)

