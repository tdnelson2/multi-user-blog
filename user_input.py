import security
import creator

def likes_and_comments_mgmt(page, Comments_db, Blog_db):

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
            if security.eval_permissions(page, entry.author_id):
                entry_id_hash = make_secure_val(str(post_id))
                page.redirect('/bogspot/edit-post/%s' % entry_id_hash)
        elif "delete" == arguments[1]:
            if security.eval_permissions(page, entry.author_id):
                entry.delete()
                page.redirect('/bogspot/dialog?type=post_deleted')
        elif "comment" == arguments[1]:
            if page.user:
                page.redirect('/bogspot/%s#Comments' % str(post_id))
            else:
                page.redirect('/bogspot/login')
        elif "like" == arguments[1]:

            # pass False to override eval_permissions' redirect
            if security.eval_permissions(page, entry.author_id, False):

                # can't like your own post
                page.redirect('/bogspot/dialog?type=like')
            else:
                if page.user:
                    if creator.is_liked(entry, page.user):

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


