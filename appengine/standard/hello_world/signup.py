import re

# regex

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def evaluate_signup(username, password, verify, email):
    invalid_username = "<b>That's not a valid username.</b>"
    invalid_password = "<b>That wasn't a valid password.</b>"
    invalid_verify = "<b>Your passwords didn't match.</b>"
    invalid_email = "<b>That's not a valid email.</b>"
    
    er = False

    exceptions = {'username':'', 
                  'email':'', 
                  'username_msg':'', 
                  'password_msg':'', 
                  'email_msg':'', 
                  'verify_msg':''}

    if not USER_RE.match(username):
        er = True
        exceptions['username_msg'] = invalid_username
        exceptions['username'] = username
    if not PASSWORD_RE.match(password):
        er = True
        exceptions['password_msg'] = invalid_password
    elif password != verify:
        er = True
        exceptions['verify_msg'] = invalid_verify
    if email != "" and not EMAIL_RE.match(email):
        er = True
        exceptions['email_msg'] = invalid_email
        exceptions['email'] = email

    if not er:
        return None
    return exceptions