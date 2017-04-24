import os

import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

alphabet_lower = ["a",
                  "b",
                  "c",
                  "d",
                  "e",
                  "f",
                  "g",
                  "h",
                  "i",
                  "j",
                  "k",
                  "l",
                  "m",
                  "n",
                  "o",
                  "p",
                  "q",
                  "r",
                  "s",
                  "t",
                  "u",
                  "v",
                  "w",
                  "x",
                  "y",
                  "z"]


def concatenate_char(c, i, text):
    if c.islower():
        return text + alphabet_lower[i]
    else:
        return text + alphabet_lower[i].upper()


def rot13(text):
    rot13_text = ""
    for c in text:
        c_lower = c.lower()
        if c_lower in alphabet_lower:
            i = alphabet_lower.index(c_lower)
            if i < 13:
                rot13_text = concatenate_char(c, i + 13, rot13_text)
            else:
                re = len(alphabet_lower) - i
                rot13_text = concatenate_char(c, 13 - re, rot13_text)
        else:
            rot13_text = rot13_text + c
    return rot13_text




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
        text = rot13(text)
        self.render('rot13.html', text = text)

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/fizzbuzz', FizzBuzzHandler),
                                ('/rot', Rot13Handler)],
                                debug=True)
