def is_proper_format(text, char):
	if not char in text or text[0] == char or text[-1] == char:
		return False
	return True


def is_valid(text):
    if text == "" or " " in text:
        return False
    return True


def email_is_valid(text):
	if len(text) == 0:
		return True
	if " " in text:
		return False
	if not is_proper_format(text, "@"):
		return False
	domain = text.split("@")[1]
	if not is_proper_format(domain, "."):
		return False
	return True


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

    if not is_valid(username):
        er = True
        exceptions['username_msg'] = invalid_username
        exceptions['username'] = username
    if not is_valid(password):
        er = True
        exceptions['password_msg'] = invalid_password
    elif password != verify:
        er = True
        exceptions['verify_msg'] = invalid_verify
    if not email_is_valid(email):
        er = True
        exceptions['email_msg'] = invalid_email
        exceptions['email'] = email

    if not er:
        return None
    return exceptions