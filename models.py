from google.appengine.ext import db

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