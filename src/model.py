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
https://code.google.com/p/google-app-engine-samples/
'''
from google.appengine.ext import ndb
from uuid import uuid4
import os
import modelx
from hashlib import md5


# The timestamp of the currently deployed version
TIMESTAMP = long(os.environ.get('CURRENT_VERSION_ID').split('.')[1]) >> 28

# Base Table that would be inherited by all the tables and thus
# created, modified and version properties would by default reside.
# in the table those have inherited the Base Table
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

# Config Table is contains all the necessary information regarding our application
# The Brand Name and other details of the application that are specific to an application
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

# The user table model defines the Web site users Here 
# we have allowed user to log in either manually or using social 
# accounts, we are fetching the picture of the user using gravatar
class User(Base, modelx.UserX):
  id = ndb.IntegerProperty()
  name = ndb.StringProperty(required=True)
  username = ndb.StringProperty(required=True)
  #email = ndb.EmailProperty(indexed=True, default='')
  about_me = ndb.StringProperty()
  location = ndb.StringProperty()
  email = ndb.StringProperty(default='')
  password = ndb.StringProperty(default='')
  confirm = ndb.StringProperty(default='')

  active = ndb.BooleanProperty(default=True)
  admin = ndb.BooleanProperty(default=False)
  creator = ndb.BooleanProperty(default=False)
  manager= ndb.BooleanProperty(default=False)
  end_client = ndb.BooleanProperty(default=False)

  federated_id = ndb.StringProperty(default='')
  facebook_id = ndb.StringProperty(default='')
  googleplus_id = ndb.StringProperty(default='')
  linkedin_id = ndb.StringProperty(default='')
  twitter_id = ndb.StringProperty(default='')
  # follows = ndb.KeyProperty(kind='Follow', repeated=True)
  # followers = ndb.KeyProperty(kind='User', repeated=True)
  followers = ndb.KeyProperty(kind='User')
  followed = ndb.KeyProperty(kind='User')

  _PROPERTIES = Base._PROPERTIES.union(set([
      'name',
      'username',
      'avatar_url',
    ]))


  def avatar(self, size):
    return 'http://www.gravatar.com/avatar/' + md5(self.email).hexdigest() + '?d=mm&s=' + str(size)

  def ent_key(self):
    return self.user_db.key.urlsafe()


# Followers table would include the list of follower and following user
# follower (user who is following to some user) and following ( user who is being followed by some user)
# This would make a strong social network and would create specified circle for the user
class Followers(Base,modelx.FollowersX):
  follower_name = ndb.KeyProperty(kind='User')
  follower_id = ndb.IntegerProperty(required=True)
  followed_name = ndb.KeyProperty(kind='User')
  followed_id = ndb.IntegerProperty(required=True)
  follower_avatar = ndb.KeyProperty(kind='User')
  followed_avatar = ndb.KeyProperty(kind='User')

# Inbox would contain all the direct messages sent from one user to another user
class Inbox(Base, modelx.InboxX):
  message_title = ndb.StringProperty(required= True)
  message_body = ndb.StringProperty(required=True)
  sent_from = ndb.KeyProperty(kind='User')

# SendMessage would contain all the direct messages sent from one user to another user
class SendMessage(Base, modelx.SentX):
  message_title = ndb.StringProperty(required= True)
  message_body = ndb.StringProperty(required=True)
  sent_from = ndb.KeyProperty(kind='User')
  sent_from_id = ndb.KeyProperty(kind='User')
  sent_to = ndb.KeyProperty(kind='User')
  sent_to_id = ndb.KeyProperty(kind='User')


# Event Table would contain the Specified Event Information, like creator name and id
# Event url , venue , start and end date, type of event , if Team Event Team size and No of Teams
class Event(Base,modelx.EventX):
    '''
    Refering Google + and Facebook Event model , also 
    customizing to generate team based events performance reports and visualizations 
    '''
    name = ndb.StringProperty(indexed=True,required=True)
    logo = ndb.BlobProperty(indexed=True)
    #creator = ndb.StringProperty(indexed=True, required=True)
    creator = ndb.KeyProperty(kind="User", required=True)
    creator_id = ndb.IntegerProperty(required=True)
    #creator_id = ndb.KeyProperty(kind='User', required=True)
    event_type = ndb.StringProperty(required=True)
    teamSize = ndb.IntegerProperty()
    noofTeams = ndb.IntegerProperty()
    manager = ndb.StringProperty()
    event_url = ndb.StringProperty()
    description=ndb.StringProperty(default='')
    event_email = ndb.StringProperty(default='')
    phone = ndb.IntegerProperty(default=0000000000)
    venue = ndb.StringProperty(required=True)
    address = ndb.StringProperty()
    city = ndb.StringProperty()
    state= ndb.StringProperty()
    country = ndb.StringProperty()
    postal = ndb.IntegerProperty()
    sdate = ndb.DateProperty()
    edate = ndb.DateProperty()
    googleplus_page = ndb.StringProperty(default='')
    youtubevideo_url = ndb.StringProperty(default='')
    facebook_page = ndb.StringProperty(default='')
    twitter_id = ndb.StringProperty(default='')
    access = ndb.StringProperty(required=True)

# Sample post model for testing purposes    
class Post(Base, modelx.EventX):
    name = ndb.KeyProperty(kind="User", required=True)
    poster = ndb.StringProperty(required=True)
    postbody = ndb.StringProperty(required=True)
    posturl = ndb.StringProperty(required=True)
    sdate = ndb.DateProperty()
    edate = ndb.DateProperty()

# Event Comments are the Associated Comments in an Event
class EventComments(Base, modelx.EventX):
    name = ndb.KeyProperty(kind="User", required=True)
    user_id = ndb.KeyProperty(kind="User", required=True)
    event_id = ndb.KeyProperty(kind="Event", required=True)
    event_name = ndb.KeyProperty(kind="Event", required=True)
    comment = ndb.StringProperty(required=True)

# Event Invites model to invite site users to attend the Event
class EventInvites(Base, modelx.EventX):
    user_id = ndb.KeyProperty(kind="User", required=True)
    event_id = ndb.KeyProperty(kind="Event", required=True)
    eventName = ndb.StringProperty(required=True)
    invited_to = ndb.StringProperty(required=True)
    invitation_message = ndb.StringProperty(required=True)

# Team Register Model yet to be made
class TeamRegister(Base, modelx.TeamRegisterX):
    eventId = ndb.KeyProperty(kind="Event", required=True)
    eventName = ndb.KeyProperty(kind="Event", required=True)
    teamName = ndb.StringProperty("Team Name", required=True)
    description = ndb.StringProperty("Message")
    teamVideoURL = ndb.StringProperty("Team Video URL")
    captain = ndb.KeyProperty(kind="User")

class TeamComments(Base, modelx.TeamRegisterX):
    name = ndb.KeyProperty(kind="User", required=True)
    user_id = ndb.KeyProperty(kind="User", required=True)
    event_id = ndb.KeyProperty(kind="Event", required=True)
    team_id = ndb.KeyProperty(kind="TeamRegister", required= True)
    teamName = ndb.KeyProperty(kind="TeamRegister", required= True)
    comment = ndb.StringProperty(required=True)

class SubEvents(Base, modelx.SubEventX):
    eventId = ndb.KeyProperty(kind="Event", required=True)
    eventName = ndb.KeyProperty(kind="Event", required=True)
    teamId = ndb.KeyProperty(kind="TeamRegister", required=True)
    teamName = ndb.KeyProperty(kind="TeamRegister", required=True)
    subevent_name = ndb.StringProperty("Name", required=True)
    subevent_description = ndb.StringProperty("Description", required=True)
    



class TeamMembers(Base, modelx.TeamMembersX):
    eventId = ndb.KeyProperty(kind="Event", required = True)
    teamId = ndb.KeyProperty(kind="TeamRegister", required=True)

    # memberName = ndb.KeyProperty(kind='User')
    memberId = ndb.KeyProperty(kind='User')
    memberName = ndb.StringProperty("Member Name")

'''

poster_obj = ndb.get(post_key)
name = post.user.name

author = db.get(author_key)
stories_by_author = author.story_set.get()

'''