"""
forms.py

Web forms based on Flask-WTForms

See: http://flask.pocoo.org/docs/patterns/wtforms/
     http://wtforms.simplecodes.com/
     http://net.tutsplus.com/tutorials/python-tutorials/intro-to-flask-signing-in-and-out/
     https://flask-wtf.readthedocs.org/en/latest/


"""

from flaskext import wtf
from flaskext.wtf import validators
# from wtforms import TextField , BooleanField
from wtforms.ext.appengine.ndb import model_form

from model import User

'''
class ClassicExampleForm(wtf.Form):
    example_name = wtf.TextField('Name', validators=[validators.Required()])
    example_description = wtf.TextAreaField('Description', validators=[validators.Required()])

# App Engine ndb model form example
ExampleForm = model_form(ExampleModel, wtf.Form, field_args={
    'example_name': dict(validators=[validators.Required()]),
    'example_description': dict(validators=[validators.Required()]),
})
'''
class SignupForm(wtf.Form):
    name = wtf.TextField('name', validators=[validators.Required()])
    username = wtf.TextField('username', validators=[validators.Required()])
    email= wtf.TextField('email', validators=[validators.Required()])
    password = wtf.PasswordField('password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = wtf.PasswordField('Repeat Password')
    remember_me = wtf.BooleanField('remember_me', default = False)
 
 
 
'''     
No need to make a model that is already made

#App Engine ndb model form example
SignupForm = model_form(User, wtf.Form, field_args={
    'name':dict(validators=[validators.Required()]),
    'username': dict(validators=[validators.Required()]),
    'email': dict(validators=[validators.Required()]),
    'password': dict(validators=[validators.Required()]),
    'confirm' : dict(validators=[validators.Required()]),
    #'remember_me': dict(),
})
''' 