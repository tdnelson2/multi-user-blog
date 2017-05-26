import os
import re
import webapp2
import jinja2
import signup
import random
import string
import hashlib
import hmac
SECRET = 'imsosecret'

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(s):
    val = s.split('|')[0]
    if s == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if salt == None:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt + SECRET).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    return make_pw_hash(name, pw, h.split("|")[1]).split("|")[1] == h.split("|")[1]

def get_username_from_cookie(handler_obj, cookie_name):
    user_cookie_str = handler_obj.request.cookies.get(cookie_name)
    if user_cookie_str:
        cookie_val = check_secure_val(user_cookie_str)
        if cookie_val:
            entry = User_Account_db.get_by_id(int(cookie_val))
            if not entry == None:
                return entry.username
    return None


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Blog_db(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class User_Account_db(db.Model):
    username = db.StringProperty(required = True)
    password_s = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class MainPage(Handler):
    def render_front(self):
        entries = db.GqlQuery("select * from Blog_db order by created desc")
        self.render("blog.html", entries = entries)

    def get(self):
        self.render_front()

class NewPost(Handler):
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
            self.redirect("/blog/" + str(row.key().id()))

        else:
            error = "We need both title and a body!"
            self.render_form(error)


class SpecificPost(Handler):
    def get(self, entry_id):
        entry = Blog_db.get_by_id(int(entry_id))
        if entry:
            self.render("new-blog-entry.html", title = entry.title, body = entry.body)
        else:
            self.write("could not render page for entry id: " + entry_id)

class SignupHandler(Handler):
    def get(self):
        current_user = get_username_from_cookie(self, 'CurrentUser')
        if current_user:
            self.redirect('/blog/welcome')
        else:
            self.render('signup.html')

    def post(self):
        username = self.request.get('username', 0)
        password = self.request.get('password', 0)
        verify = self.request.get('verify', 0)
        email = self.request.get('email', 0)
        username_exists = True
        hits = db.GqlQuery("SELECT * FROM User_Account_db WHERE username='%s'" % username)
        un = []
        for e in hits:
            un.append(e)
        if not un:
            username_exists = False
        params = signup.evaluate_signup(username, password, verify, email, username_exists)
        if params is None:
            row = User_Account_db(username = username, password_s = password)
            row.put()
            # encode cookie
            current_user_s = make_secure_val(str(row.key().id()))
            self.response.headers.add_header('Set-Cookie', str('CurrentUser=%s; Path=/blog/' % current_user_s))
            self.redirect('/blog/welcome')
        else:
            self.render('signup.html',  **params)

class SignupSuccessHandler(Handler):
    def get(self):
        current_user = get_username_from_cookie(self, 'CurrentUser')
        if current_user:
            self.render('signup-success.html', username = current_user)
        else:
            self.redirect('/blog/signup')

# class LoginHandler(Handler):
#     def get(self):



app = webapp2.WSGIApplication([(r'/blog/signup', SignupHandler),
                               (r'/blog/welcome', SignupSuccessHandler),
                               (r'/blog', MainPage),
                               (r'/blog/newpost', NewPost),
                               (r'/blog/(\d+)', SpecificPost)],
                               debug = True)

