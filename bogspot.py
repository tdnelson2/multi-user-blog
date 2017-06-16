import re
import security
import creator
import models
import user_input

import webapp2

# Page handlers

# suggested by Udacity reviewer


def login_required(func):
    """
    A decorator to confirm login or redirect as needed
    """

    def login(self, *args, **kwargs):
        # Logged out users are redirected, logged in users cont. to func.
        if not self.user:
            self.redirect('/bogspot/login')
        else:
            func(self, *args, **kwargs)
    return login


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
        self.write(creator.render_str(template, **kw))

    def get_user_account(self, cookie_name):
        user_cookie_str = self.request.cookies.get(cookie_name)
        if user_cookie_str:
            cookie_val = security.Utils.check_secure_val(user_cookie_str)
            if cookie_val:
                entry = models.UserAccounts.get_by_id(int(cookie_val))

                # if user account does not exit, catch the error
                try:
                    un = entry.username
                    return entry
                except AttributeError:
                    return None
        return None

    def get_db_from_id_hash(self, id_hash, db):
        entry_id = security.Utils.check_secure_val(id_hash)
        if entry_id:
            entry = db.get_by_id(int(entry_id))
            return entry
        return None

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and security.Utils.check_secure_val(cookie_val)

    def write_login_cookie(self, user_id):
        current_user_s = security.Utils.make_secure_val(user_id)
        self.response.headers.add_header('Set-Cookie',
                                         str('CurrentUser=%s; Path=/bogspot/'
                                             % current_user_s))

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

    def er_redirect(self, post_id):
        self.redirect('/bogspot/dialog?type=unknown_error'
                      '&post_id=%s' % str(entry_id))

    def unauthorized(self):
        self.redirect('/bogspot/dialog?type=unauthorized_post')

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
        username_exists = security.authenticate_login(
            username, models.db, models.UserAccounts)
        params = security.eval_signup_or_login(username,
                                               password,
                                               verify,
                                               email,
                                               username_exists)

        # proceed to welcome, if no errors found
        if params is None:
            salt = security.Utils.make_salt()
            password_hash = security.Utils.make_pw_hash(
                username, password, salt)
            row = models.UserAccounts(username=username,
                                      password_hash=password_hash,
                                      email=email, salt=salt)
            row.put()
            self.write_login_cookie(str(row.key().id()))
            self.redirect('/bogspot/welcome')

        # show errors
        else:
            self.render('signup.html',  **params)


class LoginHandler(Handler):

    # put Login/Logout/Create Account link in the body's header.
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
        params = security.eval_signup_or_login(username, password)

        # proceed to welcome, if no errors found
        if params is None:
            user_id = security.authenticate_login(
                username, models.db, models.UserAccounts,  password)
            if user_id:
                self.write_login_cookie(user_id)
                self.redirect('/bogspot/welcome')
            else:
                self.render('login.html',
                            login_msg="<br><b>Invalid login</b>",
                            login_toggle_link='/bogspot/signup',
                            login_toggle_text='Create Account')

        # show errors
        else:
            params = self.append_signup_parms(params)
            self.render('login.html', **params)


class WelcomeHandler(Handler):

    @login_required
    def get(self):
        self.render('welcome.html', username=self.user.username)


class LogoutHandler(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         str('CurrentUser=; Path=/bogspot/'))
        self.redirect("/bogspot/login")


class MainPageHandler(Handler):

    def get(self):
        entries = creator.all_posts(
            self.user, models.db, models.Blog, models.UserAccounts)
        link = '/bogspot/login'
        if self.user:
            link = '/bogspot/newpost'
        self.render("main.html", entries=entries, new_post_button_link=link)

    @login_required
    def post(self):
        user_input.manage_post(self,
                               models.Comments,
                               models.Blog)


class MainRedirectHandler(Handler):

    def get(self):
        # need to have every page a child of bogspot for cookies
        self.redirect("/bogspot/index")


class NewPostHandler(Handler):

    @login_required
    def get(self):
        self.render_edit_form()

    @login_required
    def post(self):
        user_input.new_post(self, models.Blog)


class SpecificPostHandler(Handler):

    def get(self, entry_id):
        entry = models.Blog.get_by_id(int(entry_id))
        if entry:
            post = creator.build_post(entry,
                                      self.user,
                                      models.UserAccounts)
            if post:
                # if no error, return empty string
                error = self.request.get("error") or ""
                comments = creator.get_comments(int(entry_id), models.db,
                                                models.Comments,
                                                models.UserAccounts)

                self.render("specific-blog-entry.html", post=post,
                            user=self.user, comments=comments,
                            error=re.sub('_', ' ', error))
            else:
                er_redirect(entry_id)
        else:
            er_redirect(entry_id)

    @login_required
    def post(self, entry_id):
        user_input.manage_post(self,
                               models.Comments,
                               models.Blog)


class EditPostHandler(Handler):

    @login_required
    def get(self, entry_id_hash):
        entry = self.get_db_from_id_hash(entry_id_hash, models.Blog)
        if entry:

            # If permissions are correct allow editing
            if entry.author_id == self.user.key().id():
                self.render_edit_form(title=entry.title,
                                      body=entry.body,
                                      cancel_button_link="/bogspot/%s"
                                      % str(entry.key().id()))
            else:
                self.unauthorized()
        else:
            self.redirect('/bogspot/dialog?type=url_error')

    @login_required
    def post(self, entry_id_hash):
        user_input.edit_post(self, entry_id_hash, models.Blog)


class CommentHandler(Handler):

    @login_required
    def get(self, origin_entry_id):
        comment = self.get_db_from_id_hash(self.request.get("comment_id"),
                                           models.Comments)
        if comment:

            # If permissions are correct allow editing
            if self.user.key().id() == comment.user_id:
                self.render_edit_form(type="comment",
                                      body=comment.body,
                                      cancel_button_link="/bogspot/%s"
                                      % origin_entry_id)
            else:
                self.redirect('/bogspot/dialog?type=unauthorized_comment')
        else:
            self.unknown_error()

    @login_required
    def post(self, origin_entry_id):
        body = self.request.get("comment")
        comment_id = security.Utils.check_secure_val(
            self.request.get('comment_id'))
        if body:
            if comment_id:
                comment = models.Comments.get_by_id(int(comment_id))
                comment.body = body
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
            self.dialog("Somehow you were almost able to post "
                        "without correct permisions."
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
                               (r'/bogspot', MainRedirectHandler),
                               (r'/', MainRedirectHandler)],
                              debug=True)
