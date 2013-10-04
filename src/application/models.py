"""
models.py

App Engine datastore models
Documentation: https://developers.google.com/appengine/docs/python/ndb/entities

"""


from google.appengine.ext import ndb
from google.appengine.api import users

import functools

import flask
from flaskext import login
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
    self.admin = user_db.admin

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
    self.user_db = event_db
    self.id = event_db.key.id()
    self.name = event_db.name
    self.email = event_db.email
    
  
