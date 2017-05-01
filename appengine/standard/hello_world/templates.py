import os

import jinja2
import webapp2
import rot13
import signup

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):
    def get(self):
        items = self.request.get_all("food")
        self.render("shopping_list.html", items = items)

class FizzBuzzHandler(Handler):
    def get(self):
        n = self.request.get('n', 0)
        n = n and int(n)
        self.render('fizzbuzz.html', n = n)

class Rot13Handler(Handler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        text = ""
        text = self.request.get('text', 0)
        text = rot13.rot13(text)
        self.render('rot13.html', text = text)

class SignupHandler(Handler):
	def get(self):
		self.render('signup.html')

	def post(self):
	    username = self.request.get('username', 0)
	    password = self.request.get('password', 0)
	    verify = self.request.get('verify', 0)
	    email = self.request.get('email', 0)
	    params = signup.evaluate_signup(username, password, verify, email)
	    if params is None:
	    	self.redirect('/welcome?username=' + username)
	    else:
	    	# redirect
	    	self.render('signup.html',  **params)

class SignupSuccessHandler(Handler):
	def get(self):
		username = self.request.get('username', 0)
		self.render('signup-success.html', username = username)


app = webapp2.WSGIApplication([('/', MainPage),
                                ('/fizzbuzz', FizzBuzzHandler),
                                ('/rot', Rot13Handler),
                                ('/signup', SignupHandler),
                                ('/welcome', SignupSuccessHandler)],
                                debug=True)
