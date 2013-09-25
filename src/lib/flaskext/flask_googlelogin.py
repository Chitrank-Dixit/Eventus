"""
Flask-GoogleLogin
"""

from base64 import (urlsafe_b64encode as b64encode,
                    urlsafe_b64decode as b64decode)
from urllib import urlencode
from urlparse import parse_qsl
from functools import wraps

from flask import request, redirect, abort, current_app, url_for
from flask_login import LoginManager, make_secure_token

import requests


GOOGLE_OAUTH2_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_OAUTH2_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
GOOGLE_OAUTH2_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'
USERINFO_PROFILE_SCOPE = 'https://www.googleapis.com/auth/userinfo.profile'


class GoogleLogin(object):
    """
    Main extension class
    """

    def __init__(self, app=None, login_manager=None):
        if login_manager:
            self.login_manager = login_manager
        else:
            self.login_manager = LoginManager()

        if app:
            self._app = app
            self.init_app(app)

    def init_app(self, app, add_context_processor=True, login_manager=None):
        """
        Initialize with app configuration. Existing
        `flask_login.LoginManager` instance can be passed.
        """

        if login_manager:
            self.login_manager = login_manager
        else:
            self.login_manager = LoginManager()

        # Check if login manager has been init
        if not hasattr(app, 'login_manager'):
            self.login_manager.init_app(
                app,
                add_context_processor=add_context_processor)

        # Clear flashed messages since we redirect to auth immediately
        self.login_manager.login_message = None
        self.login_manager.needs_refresh_message = None

        # Set default unauthorized callback
        self.login_manager.unauthorized_handler(self.unauthorized_callback)

    @property
    def app(self):
        return getattr(self, '_app', current_app)

    @property
    def scopes(self):
        return self.app.config.get('GOOGLE_LOGIN_SCOPES', '')

    @property
    def client_id(self):
        return self.app.config['GOOGLE_LOGIN_CLIENT_ID']

    @property
    def client_secret(self):
        return self.app.config['GOOGLE_LOGIN_CLIENT_SECRET']

    @property
    def redirect_uri(self):
        return self.app.config.get('GOOGLE_LOGIN_REDIRECT_URI')

    @property
    def redirect_scheme(self):
        return self.app.config.get('GOOGLE_LOGIN_REDIRECT_SCHEME', 'http')

    def sign_params(self, params):
        return b64encode(urlencode(dict(sig=make_secure_token(**params),
                                        **params)))

    def parse_state(self, state):
        return dict(parse_qsl(b64decode(str(state))))

    def login_url(self, params=None, **kwargs):
        """
        Return login url with params encoded in state

        Available Google auth server params:
        response_type: code, token
        prompt: none, select_account, consent
        approval_prompt: force, auto
        access_type: online, offline
        scopes: string (separated with commas) or list
        redirect_uri: string
        login_hint: string
        """
        kwargs.setdefault('response_type', 'code')
        kwargs.setdefault('access_type', 'online')

        if 'prompt' not in kwargs:
            kwargs.setdefault('approval_prompt', 'auto')

        scopes = kwargs.pop('scopes', self.scopes.split(','))
        if USERINFO_PROFILE_SCOPE not in scopes:
            scopes.append(USERINFO_PROFILE_SCOPE)

        redirect_uri = kwargs.pop('redirect_uri', self.redirect_uri)
        state = self.sign_params(params or {})

        return GOOGLE_OAUTH2_AUTH_URL + '?' + urlencode(
            dict(client_id=self.client_id,
                 scope=' '.join(scopes),
                 redirect_uri=redirect_uri,
                 state=state,
                 **kwargs))

    def unauthorized_callback(self):
        """
        Redirect to login url with next param set as request.url
        """
        return redirect(self.login_url(params=dict(next=request.url)))

    def exchange_code(self, code, redirect_uri):
        """
        Exchanges code for token/s
        """

        token = requests.post(GOOGLE_OAUTH2_TOKEN_URL, data=dict(
            code=code,
            redirect_uri=redirect_uri,
            grant_type='authorization_code',
            client_id=self.client_id,
            client_secret=self.client_secret,
        )).json
        if not token: # or token.get('error'):
            abort(400)
        return token

    def get_userinfo(self, access_token):
        userinfo = requests.get(GOOGLE_OAUTH2_USERINFO_URL, params=dict(
            access_token=access_token,
        )).json
        if not userinfo: # or userinfo.get('error'):
            abort(400)
        return userinfo

    def get_access_token(self, refresh_token):
        """
        Use a refresh token to obtain a new access token
        """

        token = requests.post(GOOGLE_OAUTH2_TOKEN_URL, data=dict(
            refresh_token=refresh_token,
            grant_type='refresh_token',
            client_id=self.client_id,
            client_secret=self.client_secret,
        )).json

        if not token: # or token.get('error'):
            return

        return token

    def oauth2callback(self, view_func):
        """
        Decorator for OAuth2 callback. Calls `GoogleLogin.login` then
        passes results to `view_func`.
        """

        @wraps(view_func)
        def decorated(*args, **kwargs):
            params = {}

            # Check sig
            if 'state' in request.args:
                params.update(**self.parse_state(request.args.get('state')))
                if params.pop('sig', None) != make_secure_token(**params):
                    return self.login_manager.unauthorized()

            code = request.args.get('code')

            # Web server flow
            
            if code:
		# token = self.exchange_code(code, request.url)
                
                token = self.exchange_code(
                    code,
                    url_for(
                        request.endpoint,
                        _external=True,
                        _scheme=self.redirect_scheme,
                    ),
                )
                
                received = self.get_access_token(token['access_token'])
                userinfo = self.get_userinfo(received)
                params.update(token=token, userinfo=userinfo)

            # Browser flow
            else:
                if params:
                    params.update(dict(request.args.items()))
                else:
                    return '''
                    <script>
                      window.onload = function() {
                        location.href = '?' + window.location.hash.substr(1);
                      };
                    </script>
                    '''

            return view_func(**params)

        return decorated

    def user_loader(self, func):
        """
        Shortcut for `login_manager`'s `flask_login.LoginManager.user_loader`
        """
        self.login_manager.user_loader(func)
