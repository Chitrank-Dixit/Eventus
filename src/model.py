# -*- coding: utf-8 -*-
'''
Google App engine
Datastore Attribute Property reference
https://developers.google.com/appengine/docs/python/datastore/typesandpropertyclasses
Enabled admin mode to Datastore for backup and restore data

For saving large files like images, videos try blobstore
https://developers.google.com/appengine/docs/python/blobstore/

NDB Cheetsheet (MOST IMP)
https://docs.google.com/document/d/1AefylbadN456_Z7BZOpZEXDq8cR8LYu7QgI7bt5V0Iw/mobilebasic

'''
from google.appengine.ext import ndb
from uuid import uuid4
import os
import modelx


# The timestamp of the currently deployed version
TIMESTAMP = long(os.environ.get('CURRENT_VERSION_ID').split('.')[1]) >> 28


class Base(ndb.Model, modelx.BaseX):
  created = ndb.DateTimeProperty(auto_now_add=True)
  modified = ndb.DateTimeProperty(auto_now=True)
  version = ndb.IntegerProperty(default=TIMESTAMP)
  _PROPERTIES = set([
      'key',
      'id',
      'version',
      'created',
      'modified',
    ])


class Config(Base, modelx.ConfigX):
  analytics_id = ndb.StringProperty(default='')
  announcement_html = ndb.StringProperty(default='')
  announcement_type = ndb.StringProperty(default='info', choices=[
      'info', 'warning', 'success', 'danger',
    ])
  brand_name = ndb.StringProperty(default='Eventus')
  linkedin_app_id=ndb.StringProperty(default='')
  linkedin_app_secret=ndb.StringProperty(default='')
  googleplus_app_id=ndb.StringProperty(default='')
  googleplus_app_secret=ndb.StringProperty(default='')
  facebook_app_id = ndb.StringProperty(default='')
  facebook_app_secret = ndb.StringProperty(default='')
  feedback_email = ndb.StringProperty(default='')
  flask_secret_key = ndb.StringProperty(default=str(uuid4()).replace('-', ''))
  twitter_consumer_key = ndb.StringProperty(default='')
  twitter_consumer_secret = ndb.StringProperty(default='')

  _PROPERTIES = Base._PROPERTIES.union(set([
      'analytics_id',
      'announcement_html',
      'announcement_type',
      'brand_name',
      'googleplus_app_id',
      'googleplus_app_secret',
      'facebook_app_id',
      'facebook_app_secret',
      'feedback_email',
      'flask_secret_key',
      'twitter_consumer_key',
      'twitter_consumer_secret',
    ]))


class User(Base, modelx.UserX):
  id = ndb.IntegerProperty(indexed= True)
  name = ndb.StringProperty(indexed=True, required=True)
  username = ndb.StringProperty(indexed=True, required=True)
  #email = ndb.EmailProperty(indexed=True, default='')
  email = ndb.StringProperty(indexed=True, default='')
  password = ndb.StringProperty(indexed=True , default='')
  confirm = ndb.StringProperty(indexed=True , default='')

  active = ndb.BooleanProperty(default=True)
  admin = ndb.BooleanProperty(default=False)
  creator = ndb.BooleanProperty(default=False)
  manager= ndb.BooleanProperty(default=False)
  end_client = ndb.BooleanProperty(default=False)

  federated_id = ndb.StringProperty(indexed=True, default='')
  facebook_id = ndb.StringProperty(indexed=True, default='')
  googleplus_id = ndb.StringProperty(indexed=True, default='')
  linkedin_id = ndb.StringProperty(indexed=True, default='')
  twitter_id = ndb.StringProperty(indexed=True, default='')

  _PROPERTIES = Base._PROPERTIES.union(set([
      'name',
      'username',
      'avatar_url',
    ]))

class Event(Base,modelx.EventX):
    '''
    Refering Google + and Facebook Event model , also 
    customizing to generate team based events performance reports and visualizations 
    '''
    name = ndb.StringProperty(indexed=True, required=True)
    #logo = ndb.FileProperty(indexed=True)
    creator = ndb.StringProperty(indexed=True, required=True)
    creator_id = ndb.IntegerProperty(indexed=True , required=True)
    manager = ndb.StringProperty(indexed=True)
    url = ndb.StringProperty(indexed=True, default='')
    description=ndb.StringProperty(indexed=True, default='')
    phone = ndb.IntegerProperty(indexed=True,default=0000000000)
    venue = ndb.StringProperty(indexed=True, required='')
    start_date = ndb.DateTimeProperty(indexed= True)
    end_date = ndb.DateTimeProperty(indexed=True)
    googleplus_page = ndb.StringProperty(indexed=True, default='')
    facebook_page = ndb.StringProperty(indexed=True, default='')
    twitter_id = ndb.StringProperty(indexed=True, default='')
    public = ndb.BooleanProperty(default=True)
    private= ndb.BooleanProperty(default=False)
    
class Post(Base, modelx.EventX):
    body = ndb.StringProperty(indexed= True, required=True)
    