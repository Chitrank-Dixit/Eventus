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
#from wtforms.ext.appengine.ndb import model_form

from model import User, Event , Post

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
    name = wtf.TextField('Name', validators=[validators.Required()])

    #username = wtf.TextField('username', validators=[validators.Required()])
    email= wtf.html5.EmailField('Email', validators=[validators.Required()])
    password = wtf.PasswordField('Password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = wtf.PasswordField('Repeat Password', validators=[validators.Required(), validators.EqualTo('password', message='Passwords must match')])
    recaptcha = wtf.RecaptchaField()
    
 
 
class SigninForm(wtf.Form):
    name = wtf.TextField('Name',validators=[validators.Required()])
    password = wtf.PasswordField('Password',validators=[validators.Required()])
    remember_me = wtf.BooleanField('remember_me', default = False)
    


class CreateEventForm(wtf.Form):
    name = wtf.TextField('Name', validators=[validators.Required()])
    # logo = wtf.FileField('logo', )
    #creator = wtf.TextField('creator', validators=[validators.Required()])
    # manager = wtf.TextField('manager', default='')
    event_type = wtf.SelectField('Event Type', choices=[('Team Event','Team Event'), ('Conference and Workshop','Conference and Workshop'), ('Party','Party')], validators=[validators.Required()])
    event_url = wtf.html5.URLField('URL')
    description = wtf.TextAreaField('Description',default='')
    venue = wtf.TextField('Where', validators=[validators.Required()])
    sdate= wtf.html5.DateField('From')
    edate= wtf.html5.DateField('To')
    
    #phone = wtf.IntegerField('phone', default= 0000000000)
    #googleplus_page = wtf.TextField('googleplus_page', default='')
    #facebook_page = wtf.TextField('facebook_page', default='')
    #twitter_id = wtf.TextField('twitter_id', default='')
    #active = wtf.BooleanField('active',default=True)
    #public = wtf.BooleanField('public',default=True)
    #private= wtf.BooleanField('private',default=False)


class SettingsForm(wtf.Form):
    location = wtf.TextField('Location')
    about = wtf.TextAreaField('About')
    google_plus = wtf.TextField('Google +')
    facebook = wtf.TextField('Facebook')
    twitter = wtf.TextField('Twitter')



class CreatePost(wtf.Form):
    poster = wtf.TextField('Post', validators=[validators.Required()])
    postbody= wtf.TextAreaField('postbody', validators=[validators.Required()])
    posturl = wtf.html5.URLField('post url', validators=[validators.Required()])
    sdate= wtf.html5.DateField('Date' , validators=[validators.Required()] )
    edate= wtf.html5.DateField('Date' , validators=[validators.Required()] )

class MessageForm(wtf.Form):
    message_title = wtf.TextField('', validators=[validators.Required()])
    message_body =  wtf.TextAreaField('', validators=[validators.Required()])



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
