import os
import markdown
import jinja2


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

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
        self.body_br = markdown.markdown(body_html_esc)
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

def build_post(entry, user, User_Account_db):
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


def all_posts(user, db, Blog_db, User_Account_db):
    posts = db.GqlQuery("SELECT * FROM Blog_db ORDER BY created DESC")

    # test if anything was returned
    if not db_query_is_empty(posts):
        post_ary = []

        # create array of Blog_Post objects containing info to display post
        for post in posts:
            post_obj = build_post(post, user, User_Account_db)
            if post_obj:
                post_ary.append(post_obj)
        if post_ary:
            return post_ary
    return None


def get_comments(entry_id, db, Comments_db, User_Account_db):
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