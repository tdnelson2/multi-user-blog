from google.appengine.ext import db


class Blog(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author_id = db.IntegerProperty()
    likes = db.ListProperty(int)


class UserAccounts(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Comments(db.Model):
    blog_post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
