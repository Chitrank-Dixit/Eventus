"""
views.py

URL route handlers

Note that any handler params must match the URL route params.
For example the *say_hello* handler, handling the URL route '/hello/<username>',
  must be passed *username* as the argument.

"""
from google.appengine.api import users
from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError
import logging

from flask import request, render_template, flash, url_for, redirect
# from flask.ext import 
import flask,flask.views
from flask_cache import Cache

from application import app
from decorators import login_required, admin_required
from forms import ExampleForm
from models import ExampleModel


# Flask-Cache (configured to use App Engine Memcache API)
cache = Cache(app)
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


class View(flask.views.MethodView):
    def get(self):
        # check if the user is logged in or not
        #if not current_user.is_authenticated():
        #    return app.login_manager.unauthorized()
        return flask.render_template('index.html')
        

'''
class Signup(flask.views.MethodView):
    def get(self):
        return None
    
    def post(self):
'''

class Signin(flask.views.MethodView):
    def get(self):
        return None
    
    def post(self):
        error = None
        next = request.args.get('next')
        if request.method == 'POST':
            username = request.form['username']
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
        
                
class Signout(flask.views.MethodView):
    def get(self):
        return None
    
    def post(self):
        logout_user()
        return redirect('index.html')
                
       
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