"""
forms.py

Web forms based on Flask-WTForms

See: http://flask.pocoo.org/docs/patterns/wtforms/
     http://wtforms.simplecodes.com/

"""

from flaskext import wtf
from flaskext.wtf import validators
from wtforms import TextField , BooleanField
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
class CSignupForm(wtf.Form):
    username = TextField('username', validators=[validators.Required()])
    email= TextField('email', validators=[validators.Required()])
    password = TextField('password', validators=[validators.Required()])
    remember_me = BooleanField('remember_me', default = False)
   
#App Engine ndb model form example
SignupForm = model_form(User, wtf.Form, field_args={
    'username': dict(validators=[validators.Required()]),
    'email': dict(validators=[validators.Required()]),
    'password': dict(validators=[validators.Required()]),
    'remember_me': dict(),
})
 