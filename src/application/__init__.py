"""
Initialize Flask app

"""
from flask import Flask

from flask_debugtoolbar import DebugToolbarExtension
from gae_mini_profiler import profiler, templatetags
from werkzeug.debug import DebuggedApplication
#from flaskext.flask_googlelogin import GoogleLogin

app = Flask('application')
app.config.from_object('application.settings')
app.config.update(
    SECRET_KEY='SFxHRvAvD_w9JzfUhI8EiJrS',
    GOOGLE_LOGIN_CLIENT_ID='1075048200759-5hunu03e087bha87d48874veh1rvr97f.apps.googleusercontent.com',
    GOOGLE_LOGIN_CLIENT_SECRET='SFxHRvAvD_w9JzfUhI8EiJrS',
    GOOGLE_LOGIN_REDIRECT_URI='http://localhost:8080/registered/')
    
# googlelogin = GoogleLogin(app)

# Enable jinja2 loop controls extension
app.jinja_env.add_extension('jinja2.ext.loopcontrols')


@app.context_processor
def inject_profiler():
    return dict(profiler_includes=templatetags.profiler_includes())

# Pull in URL dispatch routes
import urls

# Flask-DebugToolbar (only enabled when DEBUG=True)
toolbar = DebugToolbarExtension(app)

# Werkzeug Debugger (only enabled when DEBUG=True)
if app.debug:
    app.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)

# GAE Mini Profiler (only enabled on dev server)
app.wsgi_app = profiler.ProfilerWSGIMiddleware(app.wsgi_app)
