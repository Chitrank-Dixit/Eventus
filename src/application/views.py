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

from google.appengine.api import users
from json import dumps, loads

import flask
from flaskext import login
from flaskext.login import login_url, logout_user , current_user, login_required
from flaskext import oauth

import util
import model
import config
from forms import SignupForm, SigninForm, CreateEventForm , CreatePost
# Google API python Oauth 2.0
import httplib2
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from simplekv.memory import DictStore
from flaskext.kvsession import KVSessionExtension

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

# load a logged in user
#@lm.user_loader
#def load_user(id):
#    return User.query.get(int(id))


# initialize the flask mail
#mail.init_app(app)

'''
def home():
    return redirect(url_for('list_examples'))


def say_hello(username):
    """Contrived example to demonstrate Flask's url routing capabilities"""
    return 'Hello %s' % username


@login_required
def list_examples():
    """List all examples"""
    examples = ExampleModel.query()
    form = ExampleForm()
    if form.validate_on_submit():
        example = ExampleModel(
            example_name=form.example_name.data,
            example_description=form.example_description.data,
            added_by=users.get_current_user()
        )
        try:
            example.put()
            example_id = example.key.id()
            flash(u'Example %s successfully saved.' % example_id, 'success')
            return redirect(url_for('list_examples'))
        except CapabilityDisabledError:
            flash(u'App Engine Datastore is currently in read-only mode.', 'info')
            return redirect(url_for('list_examples'))
    return render_template('list_examples.html', examples=examples, form=form)


@login_required
def edit_example(example_id):
    example = ExampleModel.get_by_id(example_id)
    form = ExampleForm(obj=example)
    if request.method == "POST":
        if form.validate_on_submit():
            example.example_name = form.data.get('example_name')
            example.example_description = form.data.get('example_description')
            example.put()
            flash(u'Example %s successfully saved.' % example_id, 'success')
            return redirect(url_for('list_examples'))
    return render_template('edit_example.html', example=example, form=form)


@login_required
def delete_example(example_id):
    """Delete an example object"""
    example = ExampleModel.get_by_id(example_id)
    try:
        example.key.delete()
        flash(u'Example %s successfully deleted.' % example_id, 'success')
        return redirect(url_for('list_examples'))
    except CapabilityDisabledError:
        flash(u'App Engine Datastore is currently in read-only mode.', 'info')
        return redirect(url_for('list_examples'))


@admin_required
def admin_only():
    """This view requires an admin account"""
    return 'Super-seekrit admin page.'


@cache.cached(timeout=60)
def cached_examples():
    """This view should be cached for 60 sec"""
    examples = ExampleModel.query()
    return render_template('list_examples_cached.html', examples=examples)


def warmup():
    """App Engine warmup handler
    See http://code.google.com/appengine/docs/python/config/appconfig.html#Warming_Requests

    """
    return ''
'''




@app.route('/')
def index():
	return flask.render_template('index.html')
	
	
@app.route('/signin/',methods=['POST','GET'])
def signin():
    if g.user is not None and g.user.is_authenticated():
        return redirect(url_for('index'))
    form=SigninForm(request.form)
    if form.validate_on_submit() and request.method == 'POST':
        session['remember_me'] = form.remember_me.data
        # model.User.retrieve_one_by('username', form.username.data) && model.User.retrieve_one_by('password', form.password.data) is not None:
        user_db = model.User.retrieve_one_by('password',form.password.data)
        if not user_db:
          flash('Please check the username or password')
          return flask.redirect(flask.url_for('signin'))
        flask_user_db = FlaskUser(user_db)
        if login.login_user(flask_user_db):
          flask.flash('Hello %s, welcome to %s' % (
            user_db.name, config.CONFIG_DB.brand_name,
            ), category='success')
          return flask.redirect(flask.url_for('index'))
        else:
          flask.flash('Sorry, but you could not sign in.', category='danger')
          return flask.redirect(flask.url_for('signin'))
    return flask.render_template('signin.html', form=form)
 
                
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
    if form.validate_on_submit() or request.method=='POST':
        signup = model.User(
             name = form.name.data,
             username = form.name.data,
             email = form.email.data,
             password = form.password.data,
             
        )
        #session['remember_me']=form.remeber_me.data
        passwd = model.User.retrieve_one_by('password',form.password.data)
        user = model.User.retrieve_one_by('email', form.email.data)

        if user != None and passwd != None:
            flash(u'User already registered with this %s email ' % form.email.data,category='error')
            return redirect(url_for('signup'))
        
        try:
            signup.put()
            #signup_id = .key.id()
            message = mail.EmailMessage(sender='chitrankdixit1@gmail.com',subject="Welcome to Eventus")
            message.to=form.email.data
            message.body="Congratulations You have been registered to Eventus"
            message.send()

            #msg = Message("You have been Registered to Eventus ",sender=config.ADMINS[0],recipients=[form.email.data])
            #msg.body="Welcome to Eventus You have successfully registered to Eventus, Please note down your credentials Username:"+form.name.data+" Password: "+form.password.data          
            flash(u'User %s successfully Registered Please check your mail for more details.' % form.name.data, category='success')
            #with app.app_context():
              #mail.send(msg)
            return redirect(url_for('index'))
        except CapabilityDisabledError:
            flash(u'App Engine Datastore is currently in read-only mode.', category='info')
            return redirect(url_for('index'))
    return flask.render_template('signup.html',form=form)


# This is user profile

@app.route('/user/<name>/<int:uid>')
@login_required
def user_profile(name,uid):
    user = model.User.retrieve_one_by('name' ,name)
    uid = model.User.retrieve_one_by('id' ,uid)
    if user == None and uid == None:
        flash('User ' + name + ' not found.')
        return redirect(url_for('index'))
    userid = current_user.id
    event_st = model.Event.query()
    event_db = event_st.filter(model.Event.creator_id == userid)
    results = event_db.fetch()
    print event_db
    if not event_db:
      flash('You have not created any Event..')
    return flask.render_template('profile.html',results= results, user = user)


'''        
class Signin_action(flask.views.MethodView):
    def get(self):
        return None
    
    def post(self):
        error = None
        next = request.args.get('next')
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['password']
            password = request.form['password']


            if authenticate(app.config['AUTH_SERVER'], username, password):
                user = User.query.filter_by(username=username).first()
                if user:
                    if login_user(DbUser(user)):
                        # do stuff
                        flash("You have logged in")
                        return redirect(next or url_for('index', error=error))
            error = "Login failed"
        return flask.render_template('index.html',login=True, next=next, error=error)
'''

@app.route('/signout',methods=['POST','GET'])
def signout():
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
'''
APPLICATION_NAME = 'Uscore_Authentication'

# See the simplekv documentation for details
store = DictStore()


# This will replace the app's session handling
KVSessionExtension(store, app)


# Update client_secrets.json with your Google API project information.
# Do not change this assignment.
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
SERVICE = build('plus', 'v1')


@app.route('/signin/google_oauth/', methods=['GET'])
def google_signin():
  """Initialize a session for the current user, and render index.html."""
  # Create a state token to prevent request forgery.
  # Store it in the session for later validation.
  state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                  for x in xrange(32))
  session['state'] = state
  # Set the Client ID, Token State, and Application Name in the HTML while
  # serving it.
  response = make_response(
      render_template("index.html",
                      CLIENT_ID=CLIENT_ID,
                      STATE=state,
                      APPLICATION_NAME=APPLICATION_NAME))
  response.headers['Content-Type'] = 'text/html'
  return response


@app.route('/connect', methods=['POST'])
def connect():
  """Exchange the one-time authorization code for a token and
  store the token in the session."""
  # Ensure that the request is not a forgery and that the user sending
  # this connect request is the expected user.
  if request.args.get('state', '') != session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  # Normally, the state is a one-time token; however, in this example,
  # we want the user to be able to connect and disconnect
  # without reloading the page.  Thus, for demonstration, we don't
  # implement this best practice.
  # del session['state']

  code = request.data

  try:
    # Upgrade the authorization code into a credentials object
    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentials = your-gmail-username@gmail.comoauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(
        json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # An ID Token is a cryptographically-signed JSON object encoded in base 64.
  # Normally, it is critical that you validate an ID Token before you use it,
  # but since you are communicating directly with Google over an
  # intermediary-free HTTPS channel and using your Client Secret to
  # authenticate yourself to Google, you can be confident that the token you
  # receive really comes from Google and is valid. If your server passes the
  # ID Token to other components of your app, it is extremely important that
  # the other components validate the token before using it.
  gplus_id = credentials.id_token['sub']

  stored_credentials = session.get('credentials')
  stored_gplus_id = session.get('gplus_id')
  if stored_credentials is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps('Current user is already connected.'),
                             200)
    response.headers['Content-Type'] = 'application/json'
    return response
  # Store the access token in the session for later use.
  session['credentials'] = credentials
  session['gplus_id'] = gplus_id
  response = make_response(json.dumps('Successfully connected user.', 200))
  response.headers['Content-Type'] = 'application/json'
  return response


@app.route('/disconnect', methods=['POST'])
def disconnect():
  """Revoke current user's token and reset their session."""

  # Only disconnect a connected user.
  credentials = session.get('credentials')
  if credentials is None:
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Execute HTTP GET request to revoke current token.
  access_token = credentials.access_token
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
  h = httplib2.Http()
  result = h.request(url, 'GET')[0]

  if result['status'] == '200':
    # Reset the user's session.
    del session['credentials']
    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response
  else:
    # For whatever reason, the given token was invalid.
    response = make_response(
        json.dumps('Failed to revoke token for given user.', 400))
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/people', methods=['GET'])
def people():
  """Get list of people user has shared with this app."""
  credentials = session.get('credentials')
  # Only fetch a list of people for connected users.
  if credentials is None:
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  try:
    # Create a new authorized API client.
    http = httplib2.Http()
    http = credentials.authorize(http)
    # Get a list of people that this user has shared with this app.
    google_request = SERVICE.people().list(userId='me', collection='visible')
    result = google_request.execute(http=http)

    response = make_response(json.dumps(result), 200)
    response.headers['Content-Type'] = 'application/json'
    return response
  except AccessTokenRefreshError:
    response = make_response(json.dumps('Failed to refresh access token.'), 500)
    response.headers['Content-Type'] = 'application/json'
    return response
'''

'''
GOOGLE_CLIENT_ID = '1075048200759-5hunu03e087bha87d48874veh1rvr97f.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'SFxHRvAvD_w9JzfUhI8EiJrS'
REDIRECT_URI = '/authorized'  # one of the Redirect URIs from Google APIs console

goauth = oauth.OAuth()

google = goauth.remote_app('Uscore_Authentication',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

@app.route('/signin/google_oauth/')
def google_signin():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()

    return res['email']


@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)



@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('index'))


@google.tokengetter
def get_access_token():
    return session.get('access_token')
'''

GOOGLE_CLIENT_ID = '284844940078.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '1AXUm5M_1tYd13xNfn3MxDj6'
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


@app.route('/signin/google/')
def signin_google():
  google_url = users.create_login_url(
      flask.url_for('google_authorized', next=util.get_next_url())
    )
  return flask.redirect(google_url)


@app.route('/_s/callback/google/authorized/')
def google_authorized():
  google_user = users.get_current_user()
  if google_user is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  user_db = retrieve_user_from_googleopen(google_user)
  return signin_user_db(user_db)


def retrieve_user_from_googleopen(google_user):
  user_db = model.User.retrieve_one_by('federated_id', google_user.user_id())
  if user_db:
    if not user_db.admin and users.is_current_user_admin():
      user_db.admin = True
      user_db.put()
    return user_db

  return create_user_db(
      google_user.nickname().split('@')[0].replace('.', ' ').title(),
      google_user.nickname(),
      google_user.email(),
      federated_id=google_user.user_id(),
      admin=users.is_current_user_admin(),
    )






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
    flask.flash('Hello %s, welcome to %s' % (
        user_db.name, config.CONFIG_DB.brand_name,
      ), category='success')
    return flask.redirect(flask.url_for('index'))
  else:
    flask.flash('Sorry, but you could not sign in.', category='danger')
    return flask.redirect(flask.url_for('signin'))                
 



'''        
class Login(flask.views.MethodView):
    def get(self):
        return None

    def post(self):
        # Create a state token to prevent request forgery.
        # Store it in the session for later validation.
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                  for x in xrange(32))
        session['state'] = state
        # Set the Client ID, Token State, and Application Name in the HTML while
        # serving it.
        response = make_response(render_template('index.html',CLIENT_ID='1075048200759-5hunu03e087bha87d48874veh1rvr97f.apps.googleusercontent.com', STATE=state, APPLICATION_NAME='uscore_signin'))
        response.headers['Content-Type']='text/html'
        return response, session
'''

logger = logging.getLogger(__name__)

'''
class Login(BaseViewMixin):
    def get(self):
        return None
        
    def post(self):
        logger.debug('GET: %s' % request.args)
        params = {
            'response_type': 'code',
            'client_id': settings.GOOGLE_API_CLIENT_ID,
            'redirect_uri': url_for('auth', _external=True),
            'scope': settings.GOOGLE_API_SCOPE,
            'state': request.args.get('next'),
        }
        logger.debug('Login Params: %s' % params)
        url = settings.GOOGLE_OAUTH2_URL + 'auth?' + urllib.urlencode(params)

        context = {'login_url': url}
        return render_template('index.html', **context)


class Auth(flask.views.MethodView):
    def _get_token(self):
        params = {
            'code': request.args.get('code'),
            'client_id': settings.GOOGLE_API_CLIENT_ID,
            'client_secret': settings.GOOGLE_API_CLIENT_SECRET,
            'redirect_uri': url_for('auth', _external=True),
            'grant_type': 'authorization_code',
        }
        payload = urllib.urlencode(params)
        url = settings.GOOGLE_OAUTH2_URL + 'token'

        req = urllib2.Request(url, payload)  # must be POST

        return json.loads(urllib2.urlopen(req).read())

    def _get_data(self, response):
        params = {
            'access_token': response['access_token'],
        }
        payload = urllib.urlencode(params)
        url = settings.GOOGLE_API_URL + 'userinfo?' + payload

        req = urllib2.Request(url)  # must be GET

        return json.loads(urllib2.urlopen(req).read())

    def get(self):
        logger.debug('GET: %s' % request.args)

        response = self._get_token()
        logger.debug('Google Response: %s' % response)

        data = self._get_data(response)
        logger.debug('Google Data: %s' % data)

        user = User.get_or_create(data)
        login_user(user)
        logger.debug('User Login: %s' % user)
        return redirect(request.args.get('state') or url_for('index'))
'''        
"""
class OpenIDLogin(flask.views.MethodView):
  def get(self):
    cont = self.request.get('continue')
    logging.info('creating login form, cont: %s' % cont)
    template_values = {
      'continue': cont
    }

    path = os.path.join(os.path.dirname(__file__), 'templates', 'login.html')
    logging.info('Rendering template with path: %s' % path)
    self.response.out.write(template.render(path, template_values))      

  def post(self):
    cont = self.request.get('continue')
    logging.info('OpenIDLogin handler called, cont: %s' % cont)
    openid = self.request.get('openid_url')
    if openid:
      logging.info('creating login url for openid: %s' % openid)
      login_url = users.create_login_url(cont, None, openid)
      logging.info('redirecting to url: %s' % login_url)
      self.redirect(login_url)
    else:
      self.error(400)
"""

# Creating user events in Eventus 


@login_required
def create_event():
  form= CreateEventForm(request.form)
  if form.validate_on_submit() and request.method=='POST':
    event = model.Event(
        name = form.name.data,
        creator = current_user.name,
        url = form.url.data,
        creator_id = current_user.id,
        description = form.description.data,
        venue= form.venue.data,
        
        
      )
    try:
      event.put()
      #signup_id = .key.id()
      #msg = Message("Welcome to Eventus <br><br> You have successfully registered to Eventus, Please note down your credentials <br><br> Username: %s <br> Password: %s"  % form.username.data % form.password.data,sender=config.ADMINS[0],recipients=[form.email.data])
      flash(u'Event %s has been created.' % form.name.data, category='success')
      #mail.send(msg)
      return redirect(url_for('index'))
    except CapabilityDisabledError:
      flash(u'App Engine Datastore is currently in read-only mode.', category='info')
      return redirect(url_for('index'))
  return render_template('organizer_event_details.html',form=form)

  
@app.route('/poster/',methods=['POST','GET'])
def post_it():
  form = CreatePost(request.form)
  if form.validate_on_submit() and request.method=='POST':
    poster = model.Post(
        body = form.body.data
      )
    try:
      poster.put()
      flash("Poster has been populated")
      return (redirect(url_for('post_it')))
    except CapabilityDisabledError:
      flash('Error Occured while posting')
      return redirect(url_for('post_it'))
  return render_template('poster.html', form=form)
