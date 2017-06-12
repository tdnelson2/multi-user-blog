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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# regular expressions for validating login/signup
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

invalid_username = "<b>That's not a valid username.</b><br>"
username_taken = "<b>Username already exists</b><br>"
invalid_password = "<b>That wasn't a valid password.</b><br>"
invalid_verify = "<b>Your passwords didn't match.</b><br>"
invalid_email = "<b>That's not a valid email.</b><br>"

### User security

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
def authenticate_login(username, password=None):
    query = "SELECT * FROM User_Account_db WHERE username='%s'" % username
    hits = db.GqlQuery(query)
    if not db_query_is_empty(hits):
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

### Databases
class Blog_db(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author_id = db.IntegerProperty()
    likes = db.ListProperty(int)


class User_Account_db(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Comments_db(db.Model):
    blog_post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

# since len() doesn't work on GqlQuery,
# this is a hack to determine if it's empty
def db_query_is_empty(result):
    rows = []

    # start iterating through GqlQuery
    for r in result:
        rows.append(r)
        break
    if len(rows) > 0:
        return False
    return True

def is_liked(entry, user):
    if user:
        likes = entry.likes
        user_id = user.key().id()
        if user_id in likes:
            return True
    return False

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# this class is necessary since GqlQuery won't let you count items
class Blog_Post():

    """Data structure for use when rendering blog posts"""

    def __init__(self, post_id, author, title, body, created, likes, u_liked):

        self.post_id = post_id
        self.author = author
        self.title = title
        self.body = body
        self.created = created
        self.likes = likes
        self.u_liked = u_liked

    def render(self):
        self.like_c = len(self.likes)
        self.like_msg = mk_like_msg(self.like_c, self.u_liked)
        # self.like_state = "disabled"
        self.like_state = "enabled" if self.u_liked else "disabled"

        # escape all html in the body then replace line breaks with <br>
        body_html_esc = render_str("make-safe.html", text=self.body)
        self.body_br = render_line_breaks(body_html_esc)
        return render_str("post.html", entry = self)

def render_line_breaks(text):
    return re.sub('\n', '<br>', text)

def mk_like_msg(like_c, u_liked):
    if like_c == 0:
        return "No likes"
    elif like_c == 1 and u_liked == False:
        return "1 person thinks this is rad"
    elif like_c == 1 and u_liked == True:
        return "You think this is rad"
    elif like_c == 2 and u_liked == True:
        return "You and 1 other person think this is rad"
    elif like_c > 2 and u_liked == True:
        return "You and %s other people think this is rad" % str(like_c - 1)
    else:
        return "%s people think this is rad" % str(like_c)

def build_post(entry, user):
    author_ac = User_Account_db.get_by_id(int(entry.author_id))
    if author_ac:
        author = author_ac.username

        # when you see posts written by yourself, author will display as "You"
        if user and author == user.username:
            author = "You"
        return Blog_Post(entry.key().id(),
                         author, entry.title, entry.body,
                         entry.created.strftime("%b %d, %Y"), entry.likes,
                         is_liked(entry, user))
    return None


def all_posts(user):
    posts = db.GqlQuery("SELECT * FROM Blog_db ORDER BY created DESC")

    # test if anything was returned
    if not db_query_is_empty(posts):
        post_ary = []

        # create array of Blog_Post objects containing info to display post
        for post in posts:
            post_obj = build_post(post, user)
            if post_obj:
                post_ary.append(post_obj)
        if post_ary:
            return post_ary
    return None


def get_comments(entry_id):
    query = ("SELECT * FROM Comments_db "
             "WHERE blog_post_id=%d "
             "ORDER BY created ASC" % entry_id)
    hits = db.GqlQuery(query)

    # check if query returned empty
    if db_query_is_empty(hits):
        return None
    else:

        # build dictionary containing all pertainant info
        comments = []
        for hit in hits:
            username = User_Account_db.get_by_id(hit.user_id).username
            # if user no longer exists, the comment will not be shown
            if username:
                entry = {"username": username,
                         "user_id": hit.user_id,
                         "body": hit.body,
                         "id": str(hit.key().id())}
                comments.append(entry)
        if comments:
            return comments
    return None


# Page handlers
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):

        # add the login/logout to the body's header
        # if it has not already been specified

        if not "login_toggle_link" in kw and not "login_toggle_text" in kw:
            if self.user:
                kw["login_toggle_link"] = "/bogspot/logout"
                kw["login_toggle_text"] = "Log Out"
            else:
                kw["login_toggle_link"] = "/bogspot/login"
                kw["login_toggle_text"] = "Sign In"
        self.write(render_str(template, **kw))

    def get_user_account(self, cookie_name):
        user_cookie_str = self.request.cookies.get(cookie_name)
        if user_cookie_str:
            cookie_val = check_secure_val(user_cookie_str)
            if cookie_val:
                entry = User_Account_db.get_by_id(int(cookie_val))

                # if user account does not exits, catch the error
                try:
                    un = entry.username
                    return entry
                except AttributeError:
                    return None
        return None

    def get_db_from_id_hash(self, id_hash, db):
        entry_id = check_secure_val(id_hash)
        if entry_id:
            entry = db.get_by_id(int(entry_id))
            return entry
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
                    self.redirect('/bogspot/dialog?type=not_author')
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

    def render_edit_form(self, type="blog-post", error="",
                         title="", body="", cancel_button_link="/bogspot"):

        # by default this works with blog-post.html,
        # but if you pass type="comment",
        # it'll render edit-comment.html

        page = "new-post.html"
        if type == "comment":
            page = "edit-comment.html"
        self.render(page, error=error, title=title, body=body,
                    cancel_button_link=cancel_button_link)

    def unknown_error(self):
        self.redirect('/bogspot/dialog?type=unknown_error')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.user = self.get_user_account('CurrentUser')


class SignupHandler(Handler):

    def get(self):

        # check for cookie
        current_user = self.get_user_account('CurrentUser')
        if current_user:
            self.redirect('/bogspot/welcome')

        # continue to signup if no cookie found or if invalid
        else:
            self.render('signup.html', login_toggle_link='/bogspot/login',
                        login_toggle_text='Login')

    def post(self):
        username = self.request.get('username', "")
        password = self.request.get('password', "")
        verify = self.request.get('verify', "")
        email = self.request.get('email', "")
        username_exists = authenticate_login(username)
        params = eval_signup_or_login(username, password, verify, email,
                                      username_exists)

        # proceed to welcome, if no errors found
        if params is None:
            salt = make_salt()
            password_hash = make_pw_hash(username, password, salt)
            row = User_Account_db(username=username,
                                  password_hash=password_hash,
                                  email=email, salt=salt)
            row.put()
            self.write_login_cookie(str(row.key().id()))
            self.redirect('/bogspot/welcome')

        # show errors
        else:
            self.render('signup.html',  **params)


class LoginHandler(Handler):

    # put link in the body's header.
    # a link is added automatically by self.render() if you don't overrided it

    def append_signup_parms(self, params):
        params['login_toggle_link'] = '/bogspot/signup'
        params['login_toggle_text'] = 'Create Account'
        return params

    def get(self):

        # check for cookie
        current_user = self.get_user_account('CurrentUser')
        if current_user:
            self.redirect('/bogspot/welcome')

        # continue to login if no cookie found or if invalid
        else:
            self.render('login.html', login_toggle_link='/bogspot/signup',
                        login_toggle_text='Create Account')

    def post(self):
        username = self.request.get('username', 0)
        password = self.request.get('password', 0)
        params = eval_signup_or_login(username, password)

        # proceed to welcome, if no errors found
        if params is None:
            user_id = authenticate_login(username, password)
            if user_id:
                self.write_login_cookie(user_id)
                self.redirect('/bogspot/welcome')
            else:
                self.render('login.html',
                            login_msg = "<br><b>Invalid login</b>",
                            login_toggle_link = '/bogspot/signup',
                            login_toggle_text = 'Create Account')

        # show errors
        else:
            params = self.append_signup_parms(params)
            self.render('login.html', **params)


class WelcomeHandler(Handler):

    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.username,
                        login_toggle_link = '/bogspot/logout',
                        login_toggle_text = 'Logout')
        else:
            self.redirect('/bogspot/signup')


class LogoutHandler(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         str('CurrentUser=; Path=/bogspot/'))
        self.redirect("/bogspot/login")


class MainPageHandler(Handler):

    def get(self):
        entries = all_posts(self.user)
        link = '/bogspot/login'
        if self.user:
            link = '/bogspot/newpost'
        self.render("main.html", entries=entries, new_post_button_link = link)

    def post(self):
        likes_and_comments_mgmt(self)

def likes_and_comments_mgmt(page):

    arguments = page.request.arguments()[0].split("=")

    # Argument format:
    # COMMENT:
    # "comment=delete=1234567890=987654321"
    #    ^          ^         ^         ^
    #  type | button press | post id | comment id

    # BLOG POST
    # "post=delete=1234565445457890"
    #   ^        ^             ^
    #  type | button press | post id

    # split at "=" to get our arugments

    # test for arguments
    if len(arguments) == 4 and "comment" == arguments[0]:
        try:
            post_id = int(arguments[2])
            comment_id = int(arguments[3])
        except ValueError:
            page.redirect('/bogspot/dialog?type=unknown_error'
                          '&post_id=%s&comment_id=%s'
                           % (arguments[2], arguments[3]))
            return None
        if "delete" == arguments[1]:
            comment = Comments_db.get_by_id(comment_id)
            comment.delete()
            page.redirect('/bogspot/dialog?type=comment_deleted')
        elif "edit" == arguments[1]:
            comment_id_hash = ("%s?comment_id=%s" % (str(post_id), 
                                make_secure_val(str(comment_id))))
            page.redirect('/bogspot/comment/%s' % comment_id_hash)
        elif "new" == arguments[1] or "new-text" == arguments[1]:

            comment = page.request.get("comment=new-text=%s=0" % str(post_id))

            # save comment if it contains text
            if comment:
                row = Comments_db(blog_post_id=post_id,
                                  user_id=page.user.key().id(),
                                  body=comment)
                row.put()
                page.redirect('/bogspot/dialog?type=comment_added')
            else:
                page.redirect('/bogspot/%s?error=Comment_contains_no_text#Comments'
                              % str(post_id))
    elif len(arguments) == 3 and "post" == arguments[0]:
        try:
            post_id = int(arguments[2])
        except ValueError:
            page.redirect('/bogspot/dialog?type=unknown_error&post_id=%s'
                           % arguments[2])
            return None
        entry = Blog_db.get_by_id(post_id)
        if "edit" == arguments[1]:

            # eval_permissions will kick you to login if returns false
            if page.eval_permissions(entry.author_id):
                entry_id_hash = make_secure_val(str(post_id))
                page.redirect('/bogspot/edit-post/%s' % entry_id_hash)
        elif "delete" == arguments[1]:
            if page.eval_permissions(entry.author_id):
                entry.delete()
                page.redirect('/bogspot/dialog?type=post_deleted')
        elif "comment" == arguments[1]:
            if page.user:
                page.redirect('/bogspot/%s#Comments' % str(post_id))
            else:
                page.redirect('/bogspot/login')
        elif "like" == arguments[1]:

            # pass False to override eval_permissions' redirect
            if page.eval_permissions(entry.author_id, False):

                # can't like your own post
                page.redirect('/bogspot/dialog?type=like')
            else:
                if page.user:
                    if page.is_liked(entry):

                        # already liked, unklike
                        entry.likes.remove(page.user.key().id())
                        entry.put()
                        page.redirect('/bogspot/dialog?type=unliked')
                    else:

                        # like
                        entry.likes.append(page.user.key().id())
                        entry.put()
                        page.redirect('/bogspot/dialog?type=liked')
                else:
                    page.redirect('/bogspot/login')
    else:
        page.redirect('/bogspot/dialog?type=unknown_error')


class MainRedirectHandler(Handler):

    def get(self):

        # need to have every page a child of bogspot for cookies
        self.redirect("/bogspot/index")


class NewPostHandler(Handler):

    def get(self):
        self.render_edit_form()

    def post(self):
        title = self.request.get("subject")
        body = self.request.get("content")

        if title and body:
            row = Blog_db(title=title,
                          body=body,
                          author_id=self.user.key().id())
            row.put()
            self.redirect("/bogspot/" + str(row.key().id()))
        else:
            self.render_edit_form(error="We need both title and a body!",
                                  title=title,
                                  body=body)


class SpecificPostHandler(Handler):

    def get(self, entry_id):
        entry = Blog_db.get_by_id(int(entry_id))
        if entry:
            post = build_post(entry, self.user)
            if post:
                # if no error, return empty string
                error = self.request.get("error") or ""
                comments = get_comments(int(entry_id))

                self.render("specific-blog-entry.html", post=post,
                            user=self.user, comments=comments,
                            error=re.sub('_', ' ', error))
            else:
                self.write("could not render page for entry id: " + entry_id)
        else:
            self.write("could not render page for entry id: " + entry_id)

    def post(self, entry_id):
        likes_and_comments_mgmt(self)



class EditPostHandler(Handler):

    def get(self, entry_id_hash):
        entry = self.get_db_from_id_hash(entry_id_hash, Blog_db)
        if entry:

            # If permissions are correct allow editing
            if entry.author_id == self.user.key().id():
                self.render_edit_form(title = entry.title,
                                      body = entry.body,
                                      cancel_button_link = "/bogspot/%s"
                                      % str(entry.key().id()))
            else:
                self.redirect('/bogspot/dialog?type=unauthorized_post')
        else:
            self.redirect('/bogspot/dialog?type=url_error')

    def post(self, entry_id_hash):
        title = self.request.get("subject")
        body = self.request.get("content")
        entry_id = check_secure_val(entry_id_hash)
        if title and body:

            # if id is valid, save the comment
            if entry_id:
                entry = Blog_db.get_by_id(int(entry_id))
                entry.title = title
                entry.body = body
                entry.put()
                self.redirect('/bogspot/dialog?type=post_edit_success')
            else:
                self.redirect('/bogspot/dialog?type=unauthorized_post')
        else:
            self.render_edit_form(error="We need both title and a body!",
                                  title=title, body=body,
                                  cancel_button_link="/bogspot/%s"
                                  % entry_id)


class CommentHandler(Handler):

    def get(self, origin_entry_id):
        comment = self.get_db_from_id_hash(self.request.get("comment_id"),
                                           Comments_db)
        if comment:
            if self.user:

                # If permissions are correct allow editing
                if self.user.key().id() == comment.user_id:
                    self.render_edit_form(type="comment",
                                          body=comment.body,
                                          cancel_button_link="/bogspot/%s"
                                          % origin_entry_id)
                else:
                    self.redirect('/bogspot/dialog?type=unauthorized_comment')
            else:
                self.redirect('/bogspot/login')
        else:
            self.unknown_error()

    def post(self, origin_entry_id):
        body = self.request.get("comment")
        comment_id = check_secure_val(self.request.get('comment_id'))
        if body:
            if comment_id:
                comment = Comments_db.get_by_id(int(comment_id))
                comment.body = render_line_breaks(body)
                comment.put()
                self.redirect("/bogspot/dialog?type=comment_edit_success")
            else:
                self.redirect('/bogspot/dialog?type=unauthorized_comment')
        else:
            self.render_edit_form(type="comment",
                                  error="You forgot to put text in "
                                  "the comment box, doofus!",
                                  cancel_button_link="/bogspot/%s"
                                  % origin_entry_id)


class DialogHandler(Handler):

    # Dialog text is determined by querying the url for it's type

    def dialog(self, msg):
        self.render('dialog.html', msg=msg)

    def get(self):
        type = self.request.get('type')
        if type == 'not_author':
            self.dialog("You are not authorized to modify this post!")
        elif type == 'like':
            self.dialog("You can't like your own post. That's just silly.")
        elif type == 'liked':
            self.dialog("Thanks for the positive feedback!")
        elif type == 'unliked':
            self.dialog("I'm sorry you no longer think this post is rad.")
        elif type == 'comment_added':
            self.dialog("Thanks for contributing to the discussion!")
        elif type == 'post_deleted':
            self.dialog("Your bogspot post has been deleted")
        elif type == 'comment_deleted':
            self.dialog("Your comment has been deleted")
        elif type == 'edit_not_authorized':
            self.dialog("You are not authorized to edit this post. Sorry.")
        elif type == 'unauthorized_comment':
            self.dialog("You are not authorized to edit this comment. Sorry.")
        elif type == 'comment_edit_success':
            self.dialog("Your comment has been updated.\nThat's just swell.")
        elif type == 'post_edit_success':
            self.dialog("Your post has been updated. You da best!")
        elif type == 'unauthorized_post':
            self.dialog("Somehow you were almost able to post this "
                        "without correct permisions. "
                        "\nAre you a hacker? If so, I'm screwed.")
        elif type == 'unknown_error':
            self.dialog('Something went wrong.\nError code: "OH SHIT!"')
        elif type == 'url_error':
            self.dialog('The URL for this entry has been tampered with')


app = webapp2.WSGIApplication([(r'/bogspot/signup', SignupHandler),
                               (r'/bogspot/login', LoginHandler),
                               (r'/bogspot/logout', LogoutHandler),
                               (r'/bogspot/welcome', WelcomeHandler),
                               (r'/bogspot/index', MainPageHandler),
                               (r'/bogspot/newpost', NewPostHandler),
                               (r'/bogspot/(\d+)', SpecificPostHandler),
                               (r'/bogspot/edit-post/(\w+)', EditPostHandler),
                               (r'/bogspot/comment/(\w+)', CommentHandler),
                               (r'/bogspot/dialog', DialogHandler),
                               (r'/bogspot/', MainRedirectHandler),
                               (r'/bogspot', MainRedirectHandler)],
                              debug=True)
