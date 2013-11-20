"""
models.py

App Engine datastore models
Documentation: https://developers.google.com/appengine/docs/python/ndb/entities

"""


from google.appengine.ext import ndb
from google.appengine.ext import blobstore
from google.appengine.api import users

import functools

import flask
from flaskext import login
from flaskext.login import current_user
from flaskext import oauth
from hashlib import md5
import util
import model
import config
from application import app
import urls
# from application.metadata import Session, Base


################################################################################
# Flaskext Login
################################################################################
login_manager = login.LoginManager()


class AnonymousUser(login.AnonymousUserMixin):
  id = 0
  admin = False
  name = 'Anonymous'
  user_db = None

  def key(self):
    return None

login_manager.anonymous_user = AnonymousUser


class FlaskUser(AnonymousUser):
  def __init__(self, user_db):
    self.user_db = user_db
    self.id = user_db.key.id()
    self.name = user_db.name
    self.email = user_db.email
    self.followed = user_db.followed
    self.admin = user_db.admin

  def get_name(self):
    return self.user_db.name

  def key(self):
    return self.user_db.key.urlsafe()

  def get_id(self):
    return self.user_db.key.urlsafe()

  def is_authenticated(self):
    return True

  def is_active(self):
    return self.user_db.active

  def is_anonymous(self):
    return False

  def avatar(self, size):
    return 'http://www.gravatar.com/avatar/' + md5(self.email).hexdigest() + '?d=mm&s=' + str(size)

  def follow(self, user):
    if not self.is_following(user):
      self.followed.put(user)
      return self
            
  def unfollow(self, user):
    if self.is_following(user):
      self.followed.remove(user)
      return self
            
  def is_following(self, user):
    model_ex = model.Followers.query()
    for entry in model_ex:
      if entry.follower_name.string_id() == current_user.name and entry.followed_name.string_id() == user.name:
        return True
    return False
    #return (cur_user.string_id() == current_user.name and to_follow.string_id() == user.name)
  
  def has_follower(self,user):
    model_ex = model.Followers.query()
    for entry in model_ex:
      if entry.follower_name.string_id() == user.name and entry.followed_name.string_id() == current_user.name:
        return True
    return False

  def followed_posts(self):
    return Post.query.join(followers, (followers.c.followed_id == Post.user_id)).filter(followers.c.follower_id == self.id).order_by(Post.timestamp.desc())

  def __repr__(self): # pragma: no cover
    return '<User %r>' % (self.name)    




@login_manager.user_loader
def load_user(key):
  user_db = ndb.Key(urlsafe=key).get()
  if user_db:
    return FlaskUser(user_db)
  return None


login_manager.init_app(app)
login_manager.login_view = 'signin'


def current_user_id():
  return login.current_user.id


def current_user_key():
  return login.current_user.user_db.key if login.current_user.user_db else None


def current_user_db():
  return login.current_user.user_db


def is_logged_in():
  return login.current_user.id != 0





class EventData(model.Event):
  def __init__(self, event_db):
    self.event_db = event_db
    self.id = event_db.key.id()
    self.name = event_db.name
    self.email = event_db.email
    
  def avatar(self, size):
    return 'http://www.gravatar.com/avatar/' + md5(self.email).hexdigest() + '?d=mm&s=' + str(size)

