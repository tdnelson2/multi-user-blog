import os
import re
import webapp2
import jinja2

from google.appengine.ext import db

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

class Blog_db(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
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


app = webapp2.WSGIApplication([(r'/blog', MainPage),
                               (r'/blog/newpost', NewPost),
                               (r'/blog/(\d+)', SpecificPost)], debug = True)

