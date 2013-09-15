# flask minimal application
import flask, flask.views
 #from flask import Flask, render_template
#import flask.request
#from flask.views import MethodView
import os
app = flask.Flask(__name__)

app.secret_key = "uscore"

class View(flask.views.MethodView):
    def get(self):
        return flask.render_template('index.html')

    def post(self):
        result = eval(flask.request.form['expression'])
        flask.flash(result)
        return self.get()
        
        
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
        response = make_response(
        render_template('index.html',CLIENT_ID=CLIENT_ID, STATE=state, APPLICATION_NAME=APPLICATION_NAME))

app.add_url_rule('/',view_func=View.as_view('main'),methods=['GET','POST'])
app.add_url_rule('/login/',view_func=Login.as_view('login_user'),methods= ['GET','POST'])


app.debug = True
app.run()

