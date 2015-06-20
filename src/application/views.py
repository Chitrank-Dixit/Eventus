"""
views.py

URL route handlers

Note that any handler params must match the URL route params.
For example the *say_hello* handler, handling the URL route '/hello/<username>',
  must be passed *username* as the argument.
  
only 1 page for sending the user and db data 
so no need to make one page for signup page view and other for signup data save that 
was creating problem with form name undefined

Todo

3) using Google App engine inbuilt mail feature
https://developers.google.com/appengine/docs/python/mail/sendingmail
https://developers.google.com/appengine/docs/python/mail/

4) template design for creating , editing and event profile as well.

5) fit the current_user.name in the event creator 

6) fix the redundancy issue in the database



"""

from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError
from google.appengine.api import mail , memcache
import logging
import json
import random
import string, time
from apiclient.discovery import build
from flask import make_response, request, render_template, flash, url_for, redirect, session,g, jsonify, Response
# from flask.ext import 
import flask,flask.views
# from flask_cache import Cache
# from flaskext.mail.message import Message
# Flask-mail documentation http://pythonhosted.org/flask-mail/
#from models import FlaskUser
from application import app , cache#, mail  
# from decorators import login_required, admin_required
# from forms import ExampleForm
from models import *
#from model import *
import requests

from datetime import datetime , timedelta
from google.appengine.api import users
from json import dumps, loads

import flask
from flaskext import login
from flaskext.login import login_url, logout_user , current_user, login_required
from flaskext import oauth


from hashlib import md5

import util
import model
import config
from forms import SignupForm, SigninForm, CreateEventForm , CreatePost , MessageForm, CommentForm, TeamRegisterForm, InviteUserForm, UserSettingsForm, ForgotPassword, ChangePassword, EditEventForm, SearchEventsForm
# Google API python Oauth 2.0
import httplib2

from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError


from simplekv.memory import DictStore
from flaskext.kvsession import KVSessionExtension

# Flask-Cache (configured to use App Engine Memcache API)
# cache = Cache(app)

# Mail settings specified
# message = mail.InboundEmailMessage(request.body)
app.permanent_session_lifetime = timedelta(minutes=5)

print "Requests_version",requests.__version__


@login_manager.user_loader
def load_user(key):
  user_db = ndb.Key(urlsafe=key).get()
  if user_db:
    return FlaskUser(user_db)
  return None

@app.before_request
def before_request():
    g.user = current_user


# initialize the flask mail
#mail.init_app(app)


@app.route('/')
def index():
	return flask.render_template('index.html')
	
	
@app.route('/signin/',methods=['POST','GET'])
def signin():
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form=SigninForm(request.form)
    if form.validate_on_submit() and request.method == 'POST':
        user_is = model.User.query()
        usered = user_is.filter(model.User.email == form.email.data , model.User.password == md5(form.password.data).hexdigest())
        user_in = user_is.fetch()
        #print user_in
        # model.User.retrieve_one_by('username', form.username.data) && model.User.retrieve_one_by('password', form.password.data) is not None:
        #user_db = model.User.retrieve_one_by('email' and  'password',form.email.data and md5(form.password.data).hexdigest())
        user_db = model.User.retrieve_one_by('email',form.email.data)
        if user_db.password != md5(form.password.data).hexdigest():
          flash('Incorrect Password, Please Check your password', category='error')
          return flask.redirect(flask.url_for('signin'))
        #user_is = model.User.query(model.User.name == form.name.data, model.User.password == form.password.data)
        if not user_db:
          flash('Please check the username or password')
          return flask.redirect(flask.url_for('signin'))
        flask_user_db = FlaskUser(user_db)
        if login.login_user(flask_user_db):
          flask.flash('Hello %s, welcome to %s' % (
            user_db.name, config.CONFIG_DB.brand_name,
            ), category='success')
          session['username'] = user_db.name
          return flask.redirect(flask.url_for('index'))
        else:
          flask.flash('Sorry, but you could not sign in.', category='danger')
          return flask.redirect(flask.url_for('signin'))
    forgot_form = ForgotPassword(request.form)
    if forgot_form.validate_on_submit() and request.method=='POST':
      userd = model.User.query()
      userd2 = userd.filter(model.User.email == forgot_form.email.data and model.User.password != u'') 
      userdata = userd2.fetch()
      for user in userdata:
        if user.password:
          #print user.key.id()
          message = mail.EmailMessage(sender='admin@eventfor.us',subject="Eventfor.us: Password Recovery")
          #print message
          message.to=forgot_form.email.data
          message.body = """
          Dear %s:

          Your Eventfor.us account password will be changed.

          please follow this link to confirm the password changed http://www.eventfor.us/user/%s/%s/%s and access our application's services and features.

          
          Please let us know if you have any questions.

          The Eventfor.us Team
          %s
          """ % (user.name, user.name, user.key.id() ,user.password , "http://www.eventfor.us/")
          message.send()
          flask.flash(user.name + " Password has been recovered please check your registered email" , category = "success")
        else:
          flask.flash(user.name + "with " +forgot_form.email.data + "does not exist or might signed in to the application using social signin" , category = "danger")
    return flask.render_template('signin.html', form=form,session=session, forgot_form = forgot_form)
 
                
'''
@oid.after_login
def after_login(resp):
    if resp.email is None or resp.email == "":
        flash('Invalid login. Please try again.')
        return redirect(url_for('login'))
    user = User.query.filter_by(email = resp.email).first()
    if user is None:
        nickname = resp.nickname
        if nickname is None or nickname == "":
            nickname = resp.email.split('@')[0]
        nickname = User.make_unique_nickname(nickname)
        user = User(nickname = nickname, email = resp.email, role = ROLE_USER)
        db.session.add(user)
        db.session.commit()
        # make the user follow him/herself
        db.session.add(user.follow(user))
        db.session.commit()
        
    remember_me = False
    if 'remember_me' in session:
        remember_me = session['remember_me']
        session.pop('remember_me', None)
    login_user(user, remember = remember_me)
    return redirect(request.args.get('next') or url_for('index'))
'''

@app.route('/signup/',methods = ['POST','GET'])
def signup():
    #error = None
    #signups = User.query()
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form = SignupForm(request.form)
    #next = request.args.get('next')
    if form.validate_on_submit() and request.method=='POST':
        user_db = model.User.retrieve_one_by('email', form.email.data)

        
        if user_db != None:
          if user_db.name != None and user_db.email != None and user_db.password != None:
            flash(u'User already registered with this %s email or %s name, Please choose different name and email ' % (form.email.data,form.name.data),category='error')
            return redirect(url_for('signup'))

          if user_db.name == form.name.data:
            flash('Username already taken', category='warning')
            return redirect(url_for('signup'))

          if user_db.email == form.email.data:
            flash('email alredy taken please choose different email')
            return redirect(url_for('signup'))


        
        signup = model.User(
            name = form.name.data,
            username = form.name.data,
            email = form.email.data,
            password = md5(form.password.data).hexdigest(),
            rep_password = form.password.data
             
        )
        #session['remember_me'] = form.remeber_me.data
        #passwd = model.User.retrieve_one_by('password',form.password.data)
        # user = model.User.retrieve_one_by('email', form.email.data)
        



        try:
            signup.put()
            #signup_id = .key.id()
            message = mail.EmailMessage(sender='admin@eventfor.us',subject="Welcome to Eventfor.us")
            message.to=form.email.data
            message.body = """
            Dear %s:

            Your Eventfor.us account has been approved.  You can now visit
            %s and access our application's services and features.

            Please let us know if you have any questions.

            The Eventfor.us Team
            """ % (form.name.data, "http://www.eventfor.us/")

            # message.html = """
            # <html><head></head><body>
            # Dear %s:

            # Your example.com account has been approved.  You can now visit
            # %s and access our application's services and features.

            # Please let us know if you have any questions.

            # The Eventfor.us Team
            # </body></html>
            # """ % (form.name.data, "http://www.gcdc2013-eventus.appspot.com/signin")
            
            message.send()

            #msg = Message("You have been Registered to Eventus ",sender=config.ADMINS[0],recipients=[form.email.data])
            #msg.body="Welcome to Eventus You have successfully registered to Eventus, Please note down your credentials Username:"+form.name.data+" Password: "+form.password.data          
            flash(u'User %s successfully Registered to %s, Please check your mail for more details.' % (form.name.data,config.CONFIG_DB.brand_name)  , category='success')
            #with app.app_context():
              #mail.send(msg)
            return redirect(url_for('index'))
        except CapabilityDisabledError:
            flash(u'App Engine Datastore is currently in read-only mode.', category='info')
            return redirect(url_for('index'))
    return flask.render_template('signup.html',form=form)


@app.route('/user/<name>/<int:uid>/<hexcode>', methods=['POST','GET'])
def recover_password(name,uid,hexcode):
  '''
  '''
  user = model.User.retrieve_one_by('id' and 'password' , uid and hexcode)
  form = ChangePassword(request.form)
  if form.validate_on_submit() and request.method == 'POST':
    user.password = md5(form.newpassword.data).hexdigest()
    user.put()
    flash('Password has been changed successfully !', category='success')
    return redirect(url_for('index'))
  return render_template('change_password.html', form=form, user=user)



# This is user profile
# @app.route('/user/<name>/')
@app.route('/user/<name>/<int:uid>/', methods=['GET','POST']) # /
@login_required
def user_profile(name,uid):
  if 'username' in session:
    euid= uid
    
    user_is = model.User.query()
    usered = user_is.filter(model.User.name == name , model.User.id == uid)
    user_in = user_is.fetch()
    # user = 'Initialized'
    
    user_key = ndb.Key(model.User, uid)
    comments = model.EventComments.query(model.EventComments.user_id == user_key)

    teamcomments = model.TeamComments.query(model.TeamComments.user_id == user_key)

    #print user_key
    
    #for res in user_in:
      #print res.name, res.id

    

    if user_is == None:
        flash('User ' + name + ' not found.')
        return redirect(url_for('index'))

    # specific user profile
    
    userid = current_user.id
    user = model.User.retrieve_one_by('name' and 'key' , name and user_key )
    #userid_db = ndb.Key(model.User, user.id)
    #print "-----------++++",user
    # if user.key.id() != euid:
      #flash('Invalid User', category='danger')
      #return redirect(url_for('index'))

    # Events created by the user
    event_st = model.Event.query()
    event_db = event_st.filter(model.Event.creator_id == euid)
    results = event_db.fetch()

    # followers ( user following to and user's followers )
    followers = model.Followers.query()

    #followers_current = followers.filter(model.Followers.follower_id == user.name)

    # send message to a particular User
    form= MessageForm(request.form)
    # Sending a Message to a user
    sent_from = ndb.Key(model.User, current_user.name)
    sent_to = ndb.Key(model.User, name)
    sent_from_id = ndb.Key(model.User, current_user.id)
    sent_to_id = ndb.Key(model.User, euid)
    if form.validate_on_submit() and request.method=='POST':
      message = model.SendMessage(
        message_title =  form.message_title.data,
        message_body = form.message_body.data,
        sent_from = sent_from,
        sent_from_id = sent_from_id,
        sent_to =  sent_to,
        sent_to_id = sent_to_id,

      )
      try:
        message.put()
        flash('Message Sent to %s'%(name), category='info')
        redirect(url_for('user_profile', name=name, uid=uid))
      except CapabilityDisabledError:
        flash('Something went wrong Message not delievered', category='danger')
    
    # retreive all Messages
    inbox = model.SendMessage.query()

    return flask.render_template('profile.html',results= results,
     user = user, euid= euid, followers = followers, form=form, inbox=inbox,
     user_in = user_in , comments= comments, teamcomments = teamcomments
     )
  else:
    return redirect(url_for('signin'))


@app.route('/followorunfollow/<name>/<int:uid>', methods=['POST','GET'])
@login_required
def follow_unfollow(name,uid):
  if 'username' in session:
    n=name; ui=uid
    user_is = model.User.query(model.User.name == name , model.User.id == uid)
    if user_is==None:
      return redirect(url_for('index'))
    uiid = ndb.Key(model.User, uid)
    user = model.User.retrieve_one_by('name' and 'key' ,name and uiid)

    if not current_user.is_following(user):
      if user == g.user:
        flash('You can not Unfollow Yourself',category='warning')


      cur_user = ndb.Key(model.Followers, current_user.name)
      to_follow = ndb.Key(model.Followers, user.name)
      model_ex = model.Followers.query()
      #print model_ex

      for entry in model_ex:
        if entry.follower_name.string_id() == current_user.id and entry.followed_name.string_id() == user.id:
          flash('You are Already Following %s'%(user.name), category='warning')
          return redirect(url_for('user_profile',name = n, uid= ui))


      #print ui
      follower_name = ndb.Key(model.User, current_user.name)
      followed_name = ndb.Key(model.User, user.name)
      follower_avatar = ndb.Key(model.User, current_user.avatar(80))
      followed_avatar = ndb.Key(model.User, user.avatar(80))
      follow = model.Followers(
        follower_name = follower_name,
        follower_id = current_user.id, 
        followed_name = followed_name,
        followed_id = ui,
        follower_avatar = follower_avatar,
        followed_avatar = followed_avatar,
        )
      try:
        follow.put()
        # flash('%s you are now following %s' %(current_user.name,user.name), category='info')
        redirect(url_for('user_profile', name=n, uid=ui))
      except CapabilityDisabledError:
        flash('Ahh Something Went wrong with the server',category = 'danger')  
      return redirect(url_for('user_profile',name = n, uid= ui, m=False))
      
    else:
      if user == g.user:
        flash('You can not Unfollow Yourself',category='warning')

      cur_user = ndb.Key(model.Followers, current_user.name)
      to_follow = ndb.Key(model.Followers, name)

      model_ex = model.Followers.query()
      for entry in model_ex:
        if entry.follower_name.string_id() == current_user.name and entry.followed_name.string_id() == name:
          try:
            entry.key.delete()
            flash('You are not Following %s'%(name), category='info')
          except CapabilityDisabledError:
            flash(u'App Engine Datastore is currently in read-only mode.', category='danger')
      return redirect(url_for('user_profile',name = n, uid= ui))
  else:
    return redirect(url_for('signin'))

@app.route('/follow/<name>/<int:uid>/', methods=['POST','GET'])
@login_required
def follow_user(name,uid):
  n=name; ui=uid
  user_is = model.User.query(model.User.name == name , model.User.id == uid)
  if user_is==None:
    return redirect(url_for('index'))
  uiid = ndb.Key(model.User, uid)
  user = model.User.retrieve_one_by('name' and 'key' ,name and uiid)
  
  # print '-----------Here it is',user_is
  
  if user == g.user:
    flash('You can not Unfollow Yourself',category='warning')


  # cur_user = model.Followers.follower_id.id('follower_id', current_user.get_id())
  # to_follow = model.Followers.followed_id.id('followed_id', n.get_id())
  # cur_user = 
  #site_en = model.Followers.query(model.Followers.follower_id == current_user.get_id() , model.Followers.followed_id == n.get_id())
  #site_en.key.id()
  # followornot = model.Followers.get_multi([current_user.name, user.name])
  #site_en = model.Followers.query(model.Followers.follower_id == current_user.get_id() , model.Followers.followed_id == n.get_id())
  cur_user = ndb.Key(model.Followers, current_user.name)
  to_follow = ndb.Key(model.Followers, user.name)
  model_ex = model.Followers.query()
  #site_en =  model.Followers.query(model.Followers.follower_id == (ndb.Key(model.Followers, current_user.name)), model.followed_id == ndb.Key(model.Followers, user.name)).fetch()
  #site_en = model_ex.filter(model.Followers.follower_id == cur_user, model.Followers.followed_id == to_follow)
  #print model_ex

  for entry in model_ex:
    if entry.follower_name.string_id() == current_user.id and entry.followed_name.string_id() == user.id:
      flash('You are Already Following %s'%(user.name), category='warning')
      return redirect(url_for('user_profile',name = n, uid= ui))


  #cur_user = ndb.Key(model.Followers, current_user.name)
  #to_follow = ndb.Key(model.Followers, user.name)
  #print cur_user.id() , to_follow.id()
  #print ui
  #print "-----------He it oc------------",cur_user.string_id(), to_follow
  follower_name = ndb.Key(model.User, current_user.name)
  followed_name = ndb.Key(model.User, user.name)
  follower_avatar = ndb.Key(model.User, current_user.avatar(80))
  followed_avatar = ndb.Key(model.User, user.avatar(90))
  follow = model.Followers(
    follower_name = follower_name,
    follower_id = current_user.id, 
    followed_name = followed_name,
    followed_id = ui,
    follower_avatar = follower_avatar,
    followed_avatar = followed_avatar,
    )
  try:
    follow.put()
    # flash('%s you are now following %s' %(current_user.name,user.name), category='info')
    redirect(url_for('user_profile', name=n, uid=ui))
  except CapabilityDisabledError:
    flash('Ahh Something Went wrong with the server',category = 'danger')  
  return redirect(url_for('user_profile',name = n, uid= ui, m=False))

@app.route('/unfollow/<name>/<int:uid>', methods=['POST','GET'])
@login_required
def unfollow_user(name,uid):
  n=name; ui=uid
  user_is = model.User.query(model.User.name == name , model.User.id == uid)
  if user_is==None:
    return redirect(url_for('index'))
  user = model.User.retrieve_one_by('name' ,name)
  uid = model.User.retrieve_one_by('id' ,uid)
  
  if user == g.user:
    flash('You can not Unfollow Yourself',category='warning')

  cur_user = ndb.Key(model.Followers, current_user.name)
  to_follow = ndb.Key(model.Followers, name)

  model_ex = model.Followers.query()
  for entry in model_ex:
    if entry.follower_name.string_id() == current_user.name and entry.followed_name.string_id() == name:
      try:
        entry.key.delete()
        flash('You are not Following %s'%(name), category='info')
      except CapabilityDisabledError:
        flash(u'App Engine Datastore is currently in read-only mode.', category='danger')
  return redirect(url_for('user_profile',name = n, uid= ui))

@app.route('/notifications/<name>/<int:uid>', methods=['GET','POST'])
@login_required
def user_notifications(name,uid):
  if 'username' in session:
    user_id = ndb.Key(model.User, current_user.id)
    #print user_id
    notify = model.EventInvites.query(model.EventInvites.invited_to == current_user.name, model.EventInvites.user_id == user_id)
    return render_template('notifications.html', notify=notify)
  else:
    return redirect(url_for('signin'))


@app.route('/edit_profile/<name>/<int:uid>', methods=['GET','POST'])
@login_required
def user_profile_settings(name,uid):
  if 'username' in session:
    userSettings = UserSettingsForm(request.form)
    user_is = model.User.query(model.User.name == name , model.User.id == uid)
    uiid = ndb.Key(model.User, uid)
    user = model.User.retrieve_one_by('name' and 'key' ,name and uiid)
    #print "------", user
    #
    if userSettings.validate_on_submit() and request.method == 'POST':
      #print "Scooby DOO"
      user.location = userSettings.location.data
      user.about_me = userSettings.about.data
      user.googleplus_id = userSettings.google_plusId.data
      user.facebook_id = userSettings.facebookId.data
      user.twitter_id = userSettings.twitterId.data
      user.put()
      time.sleep(2)
      flash('Profile has been updated', category="info")
      return redirect(url_for('user_profile_settings', name=name, uid=uid))
    #print user, user_is
    userSettings.about.data = user.about_me
    return render_template('edit_profile.html', userSettings=userSettings, user_is =user_is, user = user)
  else:
    return redirect(url_for('signin'))



@app.route('/signout',methods=['POST','GET'])
def signout():
  session.pop('username', None)
  login.logout_user()
  flash(u'You have been signed out.','success')
  return redirect(url_for('index'))
        
        
        
class admin(flask.views.MethodView):
  """This function renders the view to admin after singin."""
  def get(self):
    return flask.render_template('eventus-admin.html')
    
################################################################################
# Google + Signin
################################################################################


GOOGLE_CLIENT_ID = '606794653937-9a4fk719mb9uuqtc94hqha3a705enc3u.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'G1fXvejJVXNqW1TIQl34Tysj'
REDIRECT_URI = 'http://localhost:8080/oauth-authorized/'  # one of the Redirect URIs from Google APIs console


google_oauth = oauth.OAuth()

# resources can be demanded using request_token_params['scope'] ='https://www.googleapis.com/auth/userinfo.email' or
# 'https://www.googleapis.com/auth/userinfo.profile' and many more
google = google_oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email \
                          https://www.googleapis.com/auth/userinfo.profile', 
                                                
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

@app.route('/oauth-authorized/')
@google.authorized_handler
def google_oauth_authorized(resp):
  if resp is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['access_token'] = (
    resp['access_token']
    #resp['client_secret']
  )
  access_token= resp['access_token']
  session['access_token'] = access_token, ''
  if access_token:
      r = requests.get('https://www.googleapis.com/oauth2/v1/userinfo',
                         headers={'Authorization': 'OAuth ' + access_token})
      if r.ok:
          data = loads(r.text)
          #username = data['name']
          # googleuser = FlaskUser.add(**data)
  
  user_db = retrieve_user_from_google(data)
  return signin_user_db(user_db)

@app.route('/signin/googleoauth/')
def signin_googleoauth():
  '''  
  flask.session.pop('access_token', None)
  try:
    return google.authorize(
        callback=flask.url_for('google_oauth_authorized',
        next=util.get_next_url()),
      )
  except:
    flask.flash(
        'Something went terribly wrong with Twitter sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(flask.url_for('signin', next=util.get_next_url()))
  '''
  session['next'] = request.args.get('next') or request.referrer or None
  callback=url_for('google_oauth_authorized', _external=True)    
  return google.authorize(callback=callback)
  
def retrieve_user_from_google(google_user):
  user_db = model.User.retrieve_one_by('googleplus_id', google_user['id']) # google_user.user_id()
  if user_db:
    if not user_db.admin and users.is_current_user_admin():
      user_db.admin = True
      user_db.put()
    return user_db
  
  return create_user_db(
      #google_user.nickname().split('@')[0].replace('.', ' ').title(),
      google_user['given_name'],
      google_user['given_name'],
      google_user['email'],
      googleplus_id=google_user['id'],
      admin=users.is_current_user_admin(),
    )

'''

Google Plus Data
{u'family_name': u'Dixit', u'name': u'Chitrank Dixit',
u'picture': u'https://lh4.googleusercontent.com/-HuXao5NNMpQ/AAAAAAAAAAI/AAAAAAAABCE/9EqQWN1g90s/photo.jpg', u'locale': u'en', u'gender': u'male', u'email': u'chitrankdixit@gmail.com', u'birthday': u'0000-02-18', u'link': u'https://plus.google.com/113942220708315173370',
u'given_name': u'Chitrank', u'id': u'113942220708315173370', u'verified_email': True}

'''


################################################################################
# Google Signin
################################################################################


# @app.route('/signin/google/')
# def signin_google():
#   google_url = users.create_login_url(
#       flask.url_for('google_authorized', next=util.get_next_url())
#     )
#   return flask.redirect(google_url)


# @app.route('/_s/callback/google/authorized/')
# def google_authorized():
#   google_user = users.get_current_user()
#   if google_user is None:
#     flask.flash(u'You denied the request to sign in.')
#     return flask.redirect(util.get_next_url())

#   user_db = retrieve_user_from_googleopen(google_user)
#   return signin_user_db(user_db)


# def retrieve_user_from_googleopen(google_user):
#   user_db = model.User.retrieve_one_by('federated_id', google_user.user_id())
#   if user_db:
#     if not user_db.admin and users.is_current_user_admin():
#       user_db.admin = True
#       user_db.put()
#     return user_db

#   return create_user_db(
#       google_user.nickname().split('@')[0].replace('.', ' ').title(),
#       google_user.nickname(),
#       google_user.email(),
#       federated_id=google_user.user_id(),
#       admin=users.is_current_user_admin(),
#     )






################################################################################
# Twitter Signin 
################################################################################
twitter_oauth = oauth.OAuth()


twitter = twitter_oauth.remote_app(
    'twitter',
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    consumer_key='LTjPJGBUqaFXaqW7tj0gpQ',
    consumer_secret='baTEyBGq07hKGQiXAQSSe76VYBQI92P2k8Cl5ZkDgQ',
  )


@app.route('/_s/callback/twitter/oauth-authorized/')
@twitter.authorized_handler
def twitter_oauth_authorized(resp):
  if resp is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (
    resp['oauth_token'],
    resp['oauth_token_secret']
  )
  user_db = retrieve_user_from_twitter(resp)
  return signin_user_db(user_db)


@twitter.tokengetter
def get_twitter_token():
  return flask.session.get('oauth_token')


@app.route('/signin/twitter/')
def signin_twitter():
  flask.session.pop('oauth_token', None)
  try:
    return twitter.authorize(
        callback=flask.url_for('twitter_oauth_authorized',
        next=util.get_next_url()),
      )
  except:
    flask.flash(
        'Something went terribly wrong with Twitter sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(flask.url_for('signin', next=util.get_next_url()))


def retrieve_user_from_twitter(response):
  user_db = model.User.retrieve_one_by('twitter_id', response['user_id'])
  if user_db:
    return user_db

  return create_user_db(
      response['screen_name'],
      response['screen_name'],
      twitter_id=response['user_id'],
    )


################################################################################
# Facebook Signin
################################################################################
facebook_oauth = oauth.OAuth()

facebook = facebook_oauth.remote_app(
    'facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key='165055130361980',
    consumer_secret='3d18b99751acc6cfd7b0277aa1b308a8',
    request_token_params={'scope': 'email'},
  )


@app.route('/_s/callback/facebook/oauth-authorized/')
@facebook.authorized_handler
def facebook_authorized(resp):
  if resp is None:
    return 'Access denied: reason=%s error=%s' % (
      flask.request.args['error_reason'],
      flask.request.args['error_description']
    )
  flask.session['oauth_token'] = (resp['access_token'], '')
  me = facebook.get('/me')
  user_db = retrieve_user_from_facebook(me.data)
  return signin_user_db(user_db)


@facebook.tokengetter
def get_facebook_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/facebook/')
def signin_facebook():
  return facebook.authorize(callback=flask.url_for('facebook_authorized',
      next=util.get_next_url(),
      _external=True),
    )


def retrieve_user_from_facebook(response):
  user_db = model.User.retrieve_one_by('facebook_id', response['id'])
  if user_db:
    return user_db
  return create_user_db(
      response['name'],
      response['username'] if 'username' in response else response['id'],
      response['email'],
      facebook_id=response['id'],
    )


################################################################################
# Helpers
################################################################################
def create_user_db(name, username, email='', **params):
  if '@' in username:
      username = username.split('@')[0]
  new_username = username
  n = 1
  while model.User.retrieve_one_by('username', new_username) is not None:
    new_username = '%s%d' % (username, n)
    n += 1

  user_db = model.User(
      name=name,
      email=email.lower(),
      username=new_username,
      **params
    )
  user_db.put()
  return user_db


def signin_user_db(user_db):
  if not user_db:
    return flask.redirect(flask.url_for('signin'))
  flask_user_db = FlaskUser(user_db)
  if login.login_user(flask_user_db):
    session['username'] = user_db.username
    flask.flash('Hello %s, welcome to %s' % (
        user_db.name, config.CONFIG_DB.brand_name,
      ), category='success')
    return flask.redirect(flask.url_for('index'))
  else:
    flask.flash('Sorry, but you could not sign in.', category='danger')
    return flask.redirect(flask.url_for('signin'))                
 




logger = logging.getLogger(__name__)

def crop_youtube_url(url):
  '''helper function to crop the end of a youtube url video
  >> crop_youtube_url("http://www.youtube.com/watch?feature=player_embedded&v=RjoSN595F0E")
  >> 'RjoSN595F0Eh'
  '''
  code =""
  for i in range(1,25):
    if url[-i] != "=":
          code = url[-i] + code
    else :
      break
  return code

#################################################################
# Create an Event
# Delete an Event
# Live search AJAX
# Trending Events
# Event Profile
# new comments
# event specific comments
#################################################################

@app.route('/create_event/', methods=['POST','GET'])
@login_required
def create_event():
  if 'username' in session:

    form= CreateEventForm(request.form)
    #use_db = ndb.Key(urlsafe=current_user.get_id())
    use_db = ndb.Key(model.User, current_user.name)
    #id_db = ndb.Key(model.User, current_user.id)
    teamsize = 0 ; noofteams = 0
    if form.teamSize.data and form.noofTeams.data:
      teamsize = int(form.teamSize.data)
      noofteams = int(form.noofTeams.data)
     
    if request.method=='POST':
      start_date =  form.sdate.data
      sdate_list = start_date.split('/')
      end_date = form.edate.data
      edate_list = end_date.split('/')
      youtube_url_code = crop_youtube_url(form.youtubevideo_url.data)
      uploadLogo = str(form.logo.data)
      upload_url = blobstore.create_upload_url('/upload/'+uploadLogo)
      avatarKey = ndb.Key(model.User, current_user.avatar(30))
      event = model.Event(
          name = form.name.data,
          event_type = form.event_type.data,
          teamSize = teamsize,
          noofTeams = noofteams ,
          creator = use_db ,
          creator_id = current_user.id,
          event_url = form.event_url.data,
          description = form.description.data,
          venue= form.venue.data,
          address = form.address.data,
          city = form.city.data,
          state = form.state.data,
          country = form.country.data,
          postal = int(form.postal.data),
          phone =  int(form.phone.data),
          event_email = form.eventEmail.data,
          facebook_page = form.facebook_url.data,
          twitter_id = form.twitter_url.data,
          youtubevideo_url = form.youtubevideo_url.data,
          logo = upload_url,
          sdate= datetime(int(sdate_list[2]),int(sdate_list[0]),int(sdate_list[1])),
          edate= datetime(int(edate_list[2]),int(edate_list[0]),int(edate_list[1])), 
          access = form.access_type.data,
          avatar = avatarKey
        )
      event_name =  form.name.data
      try:
        record = event.put()
        # print "records is:------",record
        eid=record.integer_id()
        event_key = ndb.Key(model.Event, eid)
        # print "Key is:",event_key 
        time.sleep(4)
        #signup_id = .key.id()
        #msg = Message("Welcome to Eventus <br><br> You have successfully registered to Eventus, Please note down your credentials <br><br> Username: %s <br> Password: %s"  % form.username.data % form.password.data,sender=config.ADMINS[0],recipients=[form.email.data])
        flash(u'Event %s has been created.' % form.name.data, category='success')

        #mail.send(msg)

       
        # eventID = model.Event.query()
        # eventKey = ndb.Key(model.Event, form.name.data )
        

        # print eventKey
        
        #return redirect(url_for('event_profile', ename=form.name.data,eid=itrCid.integer_id()))
        # return redirect(url_for('index'))

        #current_event = model.Event.retrieve_one_by('name' and 'key' , event_name and event_key )
        # return redirect(url_for('index'))
        #print "Hiii",current_event

        return redirect(url_for('event_profile', ename=event_name , eid=record.integer_id()))

      except CapabilityDisabledError:
        flash(u'App Engine Datastore is currently in read-only mode.', category='info')
        return redirect(url_for('index'))
    return render_template('create_event2.html',form=form)
  else:
    return redirect(url_for('signin'))

@app.route('/delete_event/<ename>/<int:eid>', methods=['POST','GET'])
def delete_event(ename, eid):
  if 'username' in session:
    event_id = ndb.Key(model.Event, eid)
    event = model.Event.retrieve_one_by('key',event_id)
    print event
    event.key.delete()
    flash('Event has been deleted', category='danger')
    return redirect(url_for('signin'))
  else:
    return redirect(url_for('signin'))


@app.route('/pop_events1/', methods=['POST','GET'])
def pop_all_events1():
  events_data = model.Event.query()
  events_data = events_data.filter(model.Event.access == "Public")
  events_data = events_data.order(-model.Event.created)
  events_store = events_data.fetch()
  first = {}; events = []
  for event in events_store:
    first['eventname'] = event.name
    first['eventid'] = event.key.id()
    first['description'] = event.description
    first['avatar'] = event.avatar.string_id()
    first['creator'] =  event.creator.string_id()
    first['creator_id'] =  event.creator_id
    events.append(first)
    first = {}
  return jsonify(events = events)


@app.route('/events/', methods=['POST','GET'])
def trending_events():
  events= model.Event.query(model.Event.access == "Public")
  # filter(model.User.email == form.email.data , model.User.password == md5(form.password.data).hexdigest())
  return render_template('trending_events.html', events=events)

@app.route('/pop_events/', methods=['GET'])
def pop_all_events():
  events_data = model.Event.query()
  events_data = events_data.filter(model.Event.access == "Public")
  events_data = events_data.order(-model.Event.created)
  events_store = events_data.fetch()
  first = {}; events = []
  for event in events_store:
    first['eventname'] = event.name
    first['eventid'] = event.key.id()
    first['description'] = event.description
    first['avatar'] = event.avatar.string_id()
    first['creator'] =  event.creator.string_id()
    first['creator_id'] =  event.creator_id
    events.append(first)
    first = {}
  return jsonify(events = events)


# @app.route('/search_results/', methods=['GET'])
# def search_results():
#   form=SigninForm(request.form)
#   events = []
#   if form.validate_on_submit() and request.method == 'GET':
#     events_data = model.Event.query()
#     events_data = events_data.filter(model.Event.access == "Public")
#     events_data = events_data.order(-model.Event.created)
#     events_store = events_data.fetch()
#     first = {}
#     for event in events_store:
#       first['eventname'] = event.name
#       first['eventid'] = event.key.id()
#       first['description'] = event.description
#       first['avatar'] = event.avatar.string_id()
#       first['creator'] =  event.creator.string_id()
#       first['creator_id'] =  event.creator_id
#       events.append(first)
#       first = {}
#     return jsonify
#   return render_template('search_events.html', events = events)


@app.route('/search_results/', methods=['POST','GET'])
def search_results():
  # print request.form['livesearch']
  form = request.form['search_events']
  events= model.Event.query(model.Event.access == "Public", model.Event.name == form)
  print "Hello",form
  name = form
  return render_template('search_events.html', name= name)

@app.route('/jsonified_search/<ename>', methods=['GET','POST'])
def jsonified_search(ename):
  # print "In JR"
  # form=SearchEventsForm(request.form)
  # print request.form['ms'];
  events = []
  # if request.method == 'POST':
  events_data = model.Event.query()
  events_data = events_data.filter(model.Event.access == "Public", model.Event.name==ename)
  events_data = events_data.order(-model.Event.created)
  events_store = events_data.fetch()
  first = {}
  for event in events_store:
    first['eventname'] = event.name
    first['eventid'] = event.key.id()
    first['description'] = event.description
    first['avatar'] = event.avatar.string_id()
    first['creator'] =  event.creator.string_id()
    first['creator_id'] =  event.creator_id
    events.append(first)
    first = {}
  return jsonify(events=events)



@app.route('/events/<ename>/<int:eid>/', methods=['GET', 'POST'])
def event_profile(ename,eid):
  if 'username' in session:

    event_id = ndb.Key(model.Event, eid)
    event_name = ndb.Key(model.Event, ename)
    # print event_id
    # print "TESTING THINGS",eid
    events = model.Event.retrieve_one_by('name' and 'key', ename and event_id)
    # events = model.Event.query(model.Event.name == ename, model.Event.creator_id == eid)
    # comments_store = model.EventComments.query(model.EventComments.event_id == event_id)
    creator_key = ndb.Key(model.User, events.creator_id)
    event_creator = model.User.retrieve_one_by('name' and 'key', events.creator and creator_key)

    user_id = ndb.Key(model.User, current_user.id)
    name = ndb.Key(model.User, current_user.name)

    # if comments been posted
    comment_json = request.json
    # print "Here is the list",events.name
    # if user been invited
    invite_json = request.json
    
    
    # send all the Teams of an Event
    teams =  model.TeamRegister.query(model.TeamRegister.eventId == event_id )
    for team in teams:
      print team
    form = CommentForm(request.form)
    inviteform = InviteUserForm(request.form)
    # print request.json, type(comment_json)
    if request.method == 'POST' and comment_json:
      print request.json
      avatarKey = ndb.Key(model.User , request.json['avatar'])
      comments = model.EventComments(
          name = name,
          user_id = user_id,
          event_id = event_id,
          event_name = event_name,
          comment = request.json['comment'],
          avatar = avatarKey
        )
      try:
        comments.put()
        # flash('your comment has been posted', category='info')
        # mail.send(msg)
        # print name.string_id() , user_id.integer_id() , event_id
        return jsonify({ "name": name.string_id(),"uid": user_id.integer_id(), "event_id": event_id.integer_id(), "comment": request.json['comment'], "avatar": request.json['avatar'] })
      except CapabilityDisabledError:
        flash('Something went wrong and your comment has not been posted', category='danger')
        
    elif request.method == 'POST' and inviteform.validate_on_submit():
      
      invitedUser = model.User.retrieve_one_by('name' and 'email', inviteform.invite_to.data and inviteform.invite_email.data)
      print invitedUser
      invitedUserKey = invitedUser.key
      invites = model.EventInvites(
          user_id = invitedUserKey ,
          eventName =  ename,
          event_id = event_id ,
          invited_to = inviteform.invite_to.data ,
          invitation_message = inviteform.invitation_message.data
        )
      try:
        invites.put()
        # flash('your comment has been posted', category='info')
        # mail.send(msg)
        # print name.string_id() , user_id.integer_id() , event_id
        return redirect(url_for('index'))
        #return jsonify({ "name": name.string_id(),"user_id": user_id.integer_id(), "event_id": event_id.integer_id(), "comment": request.json['comment'] })
      except CapabilityDisabledError:
        flash('Something went wrong and your comment has not been posted', category='danger')
      print "Here is the list",events
    return render_template('event_profile2.html', event_creator = event_creator, events = events, ename =ename , eid= eid , form= form,  inviteform=inviteform, teams= teams )
  else:
    return redirect(url_for('signin'))

@app.route('/event_settings/<ename>/<int:eid>', methods=['POST', 'GET'])
@login_required
def event_settings(ename,eid):
  if 'username' in session:
    form= EditEventForm(request.form)
    event_id = ndb.Key(model.Event, eid)
    events = model.Event.retrieve_one_by('name' and 'key', ename and event_id)
    #description_data = form.description.data
    
    print ename, eid
    frag = str(events.sdate).split('-') 
    sdate  = frag[1]+'/'+frag[2]+'/'+frag[0]
    frag = str(events.edate).split('-') 
    edate  = frag[1]+'/'+frag[2]+'/'+frag[0]
    if form.validate_on_submit() and request.method == 'POST':
      frag= (form.sdate.data).split('/')
      sdate_new = datetime(int(frag[2]),int(frag[0]),int(frag[1]))
      frag= (form.edate.data).split('/')
      edate_new = datetime(int(frag[2]),int(frag[0]),int(frag[1]))
      events.name = form.name.data
      events.description = form.description.data
      events.sdate= sdate_new
      events.edate = edate_new
      events.event_url= form.event_url.data
      events.facebook_page = form.facebook_url.data
      events.twitter_id = form.twitter_url.data
      events.youtubevideo_url = form.youtubevideo_url.data
      events.venue = form.venue.data
      events.address = form.address.data
      events.city = form.city.data
      events.state = form.state.data
      events.country = form.country.data
      events.postal = int(form.postal.data)
      events.phone = int(form.phone.data)
      events.event_email = form.eventEmail.data
      events.access = form.access_type.data
      events.put()
      print "done"
      time.sleep(2)
      flash('Event has been updated', category='success')
      return redirect(url_for('event_profile', ename=ename, eid=eid))
    form.description.data = events.description
    return render_template('event_settings.html', events=events, sdate=sdate, edate=edate,ename=ename, eid=eid, form=form)
  else:
    return redirect(url_for('signin'))

@app.route('/comments/<int:eid>',methods=['GET'])
@login_required
@cache.cached(timeout=15, key_prefix='all_event_comments')
def all_event_comments(eid):
  event_id = ndb.Key(model.Event, eid)
  comments_store = model.EventComments.query(model.EventComments.event_id == event_id)
  first = {}; comments = []
  for comment in comments_store:
    first['name'] = comment.name.string_id()
    first['uid'] = comment.user_id.integer_id()
    first['event_id'] = comment.event_id.integer_id()
    first['comment'] = comment.comment
    first['avatar'] = comment.avatar.string_id()
    comments.append(first)
    first = {}
  return jsonify(comments=comments)


@app.route('/events/<ename>/<int:eid>/invite/', methods=['POST','GET'])
@login_required
def invite_user(ename,eid):
  if 'username' in session:

    event_id = ndb.Key(model.Event, eid)
    events = model.Event.retrieve_one_by('name' and 'key', ename and event_id)
    inviteform = InviteUserForm(request.form)
    user_id = ndb.Key(model.User, current_user.id)
    name = ndb.Key(model.User, current_user.name)
    if request.method == 'POST':
      invites = model.EventInvites(
          user_id = user_id ,
          event_id = event_id ,
          invited_to = name ,
          invitation_message = request.json['invitationMessage']
        )
      try:
        invites.put()
        # flash('your comment has been posted', category='info')
        # mail.send(msg)
        # print name.string_id() , user_id.integer_id() , event_id
        #return jsonify({ "name": name.string_id(),"user_id": user_id.integer_id(), "event_id": event_id.integer_id(), "comment": request.json['comment'] })
      except CapabilityDisabledError:
        flash('Something went wrong and your comment has not been posted', category='danger')
    return render_template('add_inviteModal.html', inviteform=inviteform)
  else:
    return redirect(url_for('signin'))


@app.route('/users', methods=['GET'])
@login_required
def get_all_users():
  if 'username' in session:

    all_users =  model.User.query()
    first = {}; users = []
    for user in all_users:
      user_key = user.key
      first['uname'] = user.name
      first['uuid'] = user_key.integer_id()
      first['about_me'] = user.about_me
      first['email'] = user.email
      users.append(first)
      first = {}
    
    return jsonify(users=users)  #(all_users =all_users)
    # Event_Type = Team Event Specifying the Teams
  else:
    return redirect(url_for('signin'))

@app.route('/events/<ename>/<int:eid>/register_team', methods=['POST','GET'])
@login_required
def RegisterTeam(ename, eid):
  if 'username' in session:
    form = TeamRegisterForm(request.form)
    event_id = ndb.Key(model.Event, eid)
    event_name = ndb.Key(model.Event, ename)
    events = model.Event.retrieve_one_by('name' and 'key', ename and event_id)
    form.teamVideoURL.data = "http://www.youtube.com/watch?v=PocfpmK458o"
  

    #team_url_code = crop_youtube_url(form.teamVideoURL.data)


    if request.method == 'POST':
      avatarKey = ndb.Key(model.User, current_user.avatar(30))
      team = model.TeamRegister(
          eventId = event_id,
          eventName = event_name,
          teamName = form.teamName.data,
          description = form.description.data,
          teamVideoURL = form.teamVideoURL.data,
          avatar = avatarKey

        )
      


      try:
        team = team.put()
        time.sleep(4)
        return redirect(url_for('Team_Profile', ename = ename , eid =  eid, teamName = form.teamName.data, tid= team.integer_id() ))
      except CapabilityDisabledError:
        flash('Something went wrong and your comment has not been posted', category='danger')

    return render_template('team_register.html', ename=ename , eid=eid, form=form, captain=current_user.name, events= events)
  else:
    return redirect(url_for('signin'))



@app.route('/events/<ename>/<int:eid>/teams/<teamName>/<int:tid>', methods=['GET', 'POST'])
@login_required
def Team_Profile(ename, eid, teamName , tid):
  if 'username' in session:

    event_id = ndb.Key(model.Event, eid)
    event_name = ndb.Key(model.Event, ename)
    team_id = ndb.Key(model.TeamRegister, tid)
    team_name = ndb.Key(model.TeamRegister, teamName)
    #print event_id
    #print "TESTING THINGS",eid
    events = model.Event.retrieve_one_by('name' and 'key', ename and event_id)
    # events = model.Event.query(model.Event.name == ename, model.Event.creator_id == eid)
    # comments_store = model.EventComments.query(model.EventComments.event_id == event_id)
    teams = model.TeamRegister.retrieve_one_by('teamName' and 'key', teamName and team_id)

    members = model.TeamMembers.query(model.TeamMembers.teamId == team_id)

    #print "All Teams", teams.teamName
    user_id = ndb.Key(model.User, current_user.id)
    name = ndb.Key(model.User, current_user.name)


@app.route('/testcrawler')
def testcrawler():
  return render_template("newtest.html")