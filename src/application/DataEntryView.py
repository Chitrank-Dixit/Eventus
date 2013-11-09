from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError
from google.appengine.api import mail
import logging
import json
import random
import string
from apiclient.discovery import build
from flask import make_response, request, render_template, flash, url_for, redirect, session,g, jsonify
# from flask.ext import 
import flask,flask.views
from flask_cache import Cache
# from flaskext.mail.message import Message
# Flask-mail documentation http://pythonhosted.org/flask-mail/
#from models import FlaskUser
from application import app #, mail  
# from decorators import login_required, admin_required
# from forms import ExampleForm
from models import *
#from model import *
import requests

from datetime import datetime
from google.appengine.api import users
from json import dumps, loads

import flask
from flaskext import login
from flaskext.login import login_url, logout_user , current_user, login_required
from flaskext import oauth



import util
import model
import config
from forms import SignupForm, SigninForm, CreateEventForm , CreatePost , MessageForm, CommentForm, TeamRegisterForm, InviteUserForm
# Google API python Oauth 2.0
import httplib2

from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError


from simplekv.memory import DictStore
from flaskext.kvsession import KVSessionExtension
import views
# Flask-Cache (configured to use App Engine Memcache API)
cache = Cache(app)

# Mail settings specified
# message = mail.InboundEmailMessage(request.body)




@login_manager.user_loader
def load_user(key):
  user_db = ndb.Key(urlsafe=key).get()
  if user_db:
    return FlaskUser(user_db)
  return None

@app.before_request
def before_request():
    g.user = current_user






# This url is used to create database entries.
@app.route('/dataentry', methods=['GET'])
def datae():
  userFromDb = model.User.query()
  # calling this function, creates the fake users
  createDemoUsers(userFromDb)
  userFromDb = model.User.query()
  
  
  for h in userFromDb :
    userKey = ndb.Key(model.User, h.name)
    cid = h.key
    cid1 = cid.integer_id()
    print 100 * "*" + str(cid1) + str(h.email)
  event = model.Event(
      name = "Event1",
      event_type = "Team Event",
      creator = userKey ,
      event_url = "https://googleplusee.com",
      description = "from testing script ",
      venue= "India ",
      sdate= datetime(2013,11,22),
      edate= datetime(2013,11,23),
      creator_id = 6395859138772992,
    ) 
      
  event.put()




  return render_template("dataentry.html", user=userFromDb)




# This is the helper function to create facke users
def createDemoUsers(userFromDb):
  # empty list containing all the email address from User table
  emailList =[]


  # creating list of emails
  for u in userFromDb:
    emailList.append(u.email)


  # creating users in database,
  # if database is not created, create it and add users
  if  ( len(emailList) == 0) :
    create_user_db(
        "test@gmail.com".split('@')[0].replace('.', ' ').title(),
        "test",
        "test@gmail.com",
        federated_id="147015317214368465184",
        
      )
    userList = ["test1@gmail.com", "test2@gmail.com","test3@gmail.com", "test4@gmail.com", "test5@gmail.com" ]
    
    for user in userList:
      randList = [] 
      randomVar = random.randint(1245678 , 8456373)
      if randomVar not in randList:
        randList.append(randomVar)
      else :
        randomVar = random.randint(1245678 , 8456373)

      user = model.User(
        name = user.split('@')[0].replace('.', ' ').title(),
        email= user,
        username=user[0:user.index('@')],
        federated_id= "1489"+ str(randomVar) +"14368465184"

        )
      user.put()

    # if database created , do not add any users
    else :
      return render_template("dataentry.html", user=userFromDb)
  

