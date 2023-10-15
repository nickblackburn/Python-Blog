import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_path = os.path.join(os.path.dirname(__file__), 'templates')
jinja_loader = jinja2.Environment(loader=jinja2.FileSystemLoader(
    template_path), autoescape=True)

secret = 'hello'

# Support functions


def load_template(template, **params):
    t = jinja_loader.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def add_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Main Handler
class BlogHandler(webapp2.RequestHandler):
    def write(self, *param1, **extraprms):
        self.response.out.write(*param1, **extraprms)

    def load_template(self, template, **params):
        params['user'] = self.user
        return load_template(template, **params)

    def use_template(self, template, **extraprms):
        self.write(self.load_template(template, **extraprms))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *param1, **extraprms):
        webapp2.RequestHandler.initialize(self, *param1, **extraprms)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# User


class User(db.Model):

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Post


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_name = db.TextProperty(required=False)
    username_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def replace_newline(self, uid, comments):
        self._new_text = self.content.replace('\n', '<br>')
        return load_template("post.html", p=self, uid=uid,
                             comments=comments)

        @classmethod
        def by_id(cls, uid):
            return Post.get_by_id(uid, parent=blog_key())

# Comment


class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    username_id = db.IntegerProperty(required=True)
    user_name = db.TextProperty(required=True)

# Like


class Like(db.Model):
    username_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

# Front Page Template - show all the posts


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.use_template('front.html', posts=posts)

# Post Page Template - post current post


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        post = db.get(key)

        if not post:
            return self.error(404)

        comments = db.GqlQuery("select * from Comment where ancestor is :1 "
                               "order by created desc limit 10", key)

        self.use_template("permalink.html", post=post, comments=comments)

# New Post Page Template - post new post


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            username = self.user.name
            self.use_template("newpost.html", username=username)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent=blog_key(), subject=subject,
                        content=content, user_name=username,
                        username_id=self.user.key().id(), username=username)
            post.put()
            return self.redirect('/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.use_template("newpost.html", subject=subject,
                              content=content, error=error)

# Edit Post Page Template - edit original post


class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        post = db.get(key)

        if not post:
            return self.error(404)

        if self.user and self.user.key().id() == post.username_id:
            username = self.user.name
            self.use_template("editpost.html", post=post,
                              subject=post.subject, content=post.content,
                              username=username, post_id=post_id)
        elif not self.user:
            return self.redirect('/login')
        else:
            error = "You do not have permission to edit this post."
            self.use_template("error.html", error=error)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        post = db.get(key)

        if not post:
        	return self.error(404)

        if self.user and self.user.key().id() == post.username_id:
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                post.subject = subject
                post.content = content
                post.user_name = self.user.name
                post.put()
                return self.redirect('/%s' % str(post.key().id()))
            else:
                error = "Error, No subject and content"
                self.use_template("newpost.html", subject=subject,
                                  content=content, error=error)
        else:
            error = "You do not have permission to edit this post."
            self.use_template("error.html", error=error)

# New Comment Template - add new comment to posds


class NewComment(BlogHandler):

    def get(self, post_id, username_id):
        if not self.user:
            self.use_template('/login')
        else:
            self.use_template("comment.html")

    def post(self, post_id, username_id):
        if not self.user:
            return self.redirect('/login')

        content = self.request.get('content')

        user_name = self.user.name
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        c = Comment(parent=key, username_id=int(username_id),
                    content=content, user_name=user_name)
        c.put()

        self.redirect('/' + post_id)

# Edit Comment Page Template - loads form to edit comment


class EditComment(BlogHandler):
    def get(self, post_id, username_id, comment_id):
        if self.user and self.user.key().id() == int(username_id):
            post = db.Key.from_path('Post', int(post_id), parent=blog_key())

            if not post:
                return self.error(404)

            key = db.Key.from_path('Comment', int(comment_id), parent=post)
            comment = db.get(key)

            if not comment:
                return self.error(404)

            self.use_template('comment.html', content=comment.content)
        elif not self.user:
            return self.redirect('/login')
        else:
            error = "You do not have permission to edit this comment."
            self.use_template("error.html", error=error)

    def post(self, post_id, username_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        if self.user and self.user.key().id() == int(username_id):
            content = self.request.get('content')

            post = db.Key.from_path('Post', int(post_id), parent=blog_key())

            if not post:
                return self.error(404)

            key = db.Key.from_path('Comment', int(comment_id), parent=post)
            comment = db.get(key)

            if not comment:
            	return self.error(404)

            comment.content = content
            comment.put()

            return self.redirect('/' + post_id)

        else:
            error = "You do not have permission to edit this comment."
            self.use_template("error.html", error=error)

# Delete Comment Page - deletes comment from post


class DeleteComment(BlogHandler):
    def get(self, post_id, username_id, comment_id):

        if self.user and self.user.key().id() == int(username_id):
            post = db.Key.from_path('Post', int(post_id), parent=blog_key())

            if not post:
                return self.error(404)

            key = db.Key.from_path('Comment', int(comment_id), parent=post)

            comment = db.get(key)

            if not comment:
            	return self.error(404)

            comment.delete()

            return self.redirect('/' + post_id)

        elif not self.user:
            return self.redirect('/login')

        else:
            error = "You do not have permission to delete this comment."
            self.use_template("error.html", error=error)

# Like Post Page - like post +1 likes


class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        post = db.get(key)

        if not post:
            return self.error(404)

        if not self.user:
            return self.redirect('/login')
        elif self.user and self.user.key().id() == post.username_id:
            error = "You do not have permission to like your own post."
            self.use_template('error.html', error=error)
        else:
            username_id = self.user.key().id()
            post_id = post.key().id()

            likepost = Like.all().filter('username_id =', username_id).filter(
                'post_id =', post_id).get()

            if likepost:
                return self.redirect('/' + str(post.key().id()))
            else:
                likepost = Like(parent=key,
                                username_id=self.user.key().id(),
                                post_id=post.key().id())

                post.likes += 1

                likepost.put()
                post.put()

                return self.redirect('/' + str(post.key().id()))

# Unlike Post Page - unlike post -1 likes


class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        post = db.get(key)

        if not post:
            return self.error(404)

        if not self.user:
            return self.redirect('/login')
        elif self.user and self.user.key().id() == post.username_id:
            error = "You do not have permission to unlike your own post."
            self.use_template('error.html', error=error)
        else:
            username_id = self.user.key().id()
            post_id = post.key().id()

            unlikepost = Like.all().filter('username_id =',
                                           username_id).filter(
                                           'post_id =', post_id).get()

            if unlikepost:
                unlikepost.delete()
                post.likes -= 1
                post.put()
                return self.redirect('/' + str(post.key().id()))
            else:
                return self.redirect('/' + str(post.key().id()))

# Delete Post Page Template - delete post


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        post = db.get(key)

        if not post:
        	return self.error(404)

        if self.user and self.user.key().id() == post.username_id:
            post.delete()
            self.use_template("delete.html")
        elif not self.user:
            return self.redirect('/login')
        else:
            error = "You do not have permission to delete this post."
            self.use_template("error.html", error=error)

# Signup Page Template - user signup


class Signup(BlogHandler):
    def get(self):
        self.use_template("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.use_template('signup-form.html', **params)
        else:
            self.done()

    def done(self, *param1, **extraprms):
        raise NotImplementedError

# Register User - Create new user, if one does not already exist


class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.use_template('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/')

# Login Page Template - user login


class Login(BlogHandler):
    def get(self):
        self.use_template('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/')
        else:
            msg = 'Invalid login'
            self.use_template('login-form.html', error=msg)

# Logout Page - user logout


class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/')

# Web App Links and Handlers


app = webapp2.WSGIApplication([
    ('/?', BlogFront),
    ('/([0-9]+)', PostPage),
    ('/newpost', NewPost),
    ('/([0-9]+)/addcomment/([0-9]+)', NewComment),
    ('/([0-9]+)/([0-9]+)/editcomment/([0-9]+)', EditComment),
    ('/([0-9]+)/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
    ('/editpost/([0-9]+)', EditPost),
    ('/likepost/([0-9]+)', LikePost),
    ('/unlikepost/([0-9]+)', UnlikePost),
    ('/deletepost/([0-9]+)', DeletePost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout)],
    debug=True)
