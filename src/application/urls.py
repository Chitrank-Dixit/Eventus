"""
urls.py

URL dispatch route mappings and error handlers

"""
from flask import render_template
from views import  Signin , Signout
from application import app
from application import views


## URL dispatch rules
# App Engine warm up handler
# See http://code.google.com/appengine/docs/python/config/appconfig.html#Warming_Requests
# app.add_url_rule('/_ah/warmup', 'warmup', view_func=views.warmup)

# Home page
# app.add_url_rule('/','home',view_func=views.home)

# Say hello
#app.add_url_rule('/hello/<username>', 'say_hello', view_func=views.say_hello)

# Examples list page
#app.add_url_rule('/examples', 'list_examples', view_func=views.list_examples, methods=['GET', 'POST'])

# Examples list page (cached)
#app.add_url_rule('/examples/cached', 'cached_examples', view_func=views.cached_examples, methods=['GET'])

# Contrived admin-only view example
#app.add_url_rule('/admin_only', 'admin_only', view_func=views.admin_only)

# Edit an example
#app.add_url_rule('/examples/<int:example_id>/edit', 'edit_example', view_func=views.edit_example, methods=['GET', 'POST'])

# Delete an example
#app.add_url_rule('/examples/<int:example_id>/delete', view_func=views.delete_example, methods=['POST'])

# This is the homepage of my custom site
# app.add_url_rule('/',view_func=views.Index.as_view('main'),methods=['GET','POST'])

# Sign in view or Social Login
app.add_url_rule('/signin/',view_func=views.Signin.as_view('signin_page'),methods=['GET','POST'])

# Sign up for new users or Social Login
app.add_url_rule('/signup/',view_func=views.Signup.as_view('signup_page'),methods=['GET','POST'])

# Sign out from Uscore
app.add_url_rule('/signout/',view_func=views.Signout.as_view('signout_page'),methods=['GET','POST'])

# This is login user url
# app.add_url_rule('/login/',view_func=views.Login.as_view('login_user'),methods= ['GET','POST'])
# This is the login user button of my custom site
# app.add_url_rule('/login/',view_func=views.Login.as_view('login_user'),methods= ['GET','POST'])

# sign up for the users
#app.add_url_rule('/signup/',view_func=views.View.as_view('signup_user').methods=['GET','POST'])

# Sign in for the users
#app.add_url_rule('/signin/',view_func=views.View.as_view('signin_user').methods=['GET','POST'])

# Sign out the users
#app.add_url_rule('/signout/',view_func=views.View.as_view('signout_user').methods=['GET','POST'])

## Error handlers
# Handle 404 errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Handle 500 errors
@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

