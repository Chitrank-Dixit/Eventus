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
    logo = wtf.FileField('logo')
    #creator = wtf.TextField('creator', validators=[validators.Required()])
    # manager = wtf.TextField('manager', default='')
    event_type = wtf.SelectField('Event Type', choices=[('Party','Party'),('Team Event','Team Event'), ('Conference and Workshop','Conference and Workshop') ], validators=[validators.Required()])
    event_url = wtf.html5.URLField('URL')
    facebook_url =  wtf.html5.URLField('URL')
    twitter_url  = wtf.html5.URLField('URL')
    youtubevideo_url = wtf.html5.URLField('URL')
    teamSize = wtf.TextField()
    noofTeams = wtf.TextField()
    description = wtf.TextAreaField('Description',default='')
    venue = wtf.TextField('Where', validators=[validators.Required()])
    address = wtf.TextField('Address', validators=[validators.Required()])
    city = wtf.TextField('City', validators=[validators.Required()])
    state = wtf.TextField('State', validators=[validators.Required()])
    country = wtf.TextField('Country',  validators=[validators.Required()])
    postal = wtf.TextField("Postal Code")
    phone = wtf.IntegerField('Phone')
    eventEmail =  wtf.html5.EmailField('Email')
    sdate= wtf.TextField('From')
    edate= wtf.TextField('To')
    access_type = wtf.SelectField('Access Type', choices=[('Public','Public'), ('Private','Private') ], validators=[validators.Required()])

    
    #phone = wtf.IntegerField('phone', default= 0000000000)
    #googleplus_page = wtf.TextField('googleplus_page', default='')
    #facebook_page = wtf.TextField('facebook_page', default='')
    #twitter_id = wtf.TextField('twitter_id', default='')
    #active = wtf.BooleanField('active',default=True)
    #public = wtf.BooleanField('public',default=True)
    #private= wtf.BooleanField('private',default=False)


class UserSettingsForm(wtf.Form):
    location = wtf.TextField('Location')
    about = wtf.TextAreaField('About')
    google_plusId = wtf.html5.URLField('Google +')
    facebookId = wtf.html5.URLField('Facebook')
    twitterId = wtf.html5.URLField('Twitter')



class CreatePost(wtf.Form):
    poster = wtf.TextField('Post', validators=[validators.Required()])
    postbody= wtf.TextAreaField('postbody', validators=[validators.Required()])
    posturl = wtf.html5.URLField('post url', validators=[validators.Required()])
    sdate= wtf.html5.DateField('Start Date' , validators=[validators.Required()] )
    edate= wtf.html5.DateField('End Date' , validators=[validators.Required()] )

class MessageForm(wtf.Form):
    message_title = wtf.TextField('', validators=[validators.Required()])
    message_body =  wtf.TextAreaField('', validators=[validators.Required()])

class CommentForm(wtf.Form):
    comment= wtf.TextAreaField('Your Comment', validators=[validators.Required()] )
    
class InviteUserForm(wtf.Form):
    invite_to = wtf.TextField('Invite User', validators=[validators.Required()])
    invite_email = wtf.html5.EmailField('Email', validators=[validators.Required()])
    invitation_message =  wtf.TextAreaField('Message', validators=[validators.Required()])


class TeamRegisterForm(wtf.Form):
    teamName = wtf.TextField('Team Name', validators=[validators.Required()])
    description= wtf.TextAreaField('Team Description')
    teamVideoURL = wtf.html5.URLField('Team Video URL')
    captain = wtf.TextField('Captain')
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
