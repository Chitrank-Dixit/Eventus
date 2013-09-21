"""
models.py

App Engine datastore models

"""


from google.appengine.ext import ndb

# from application.metadata import Session, Base


class SignupUser(ndb.Model):
    """Signup model"""
    username = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)

class SigninUser(ndb.Model):
    __tablename__ = 'uscore_users'

    user_id = ndb.IntegerProperty(required=True)
    email = ndb.StringProperty(required=True)
    username = ndb.StringProperty(required=True)

    def __init__(self, email, username):
        self.email = email
        self.username = username

    def __repr__(self):
        return "<User('%d', '%s', '%s')>" \
                % (self.user_id, self.username, self.email)

    @classmethod
    def get_or_create(cls, data):
        '''
        data contains:
            {u'family_name': u'Surname',
            u'name': u'Name Surname',
            u'picture': u'https://link.to.photo',
            u'locale': u'en',
            u'gender': u'male',
            u'email': u'propper@email.com',
            u'birthday': u'0000-08-17',
            u'link': u'https://plus.google.com/id',
            u'given_name': u'Name',
            u'id': u'Google ID',
            u'verified_email': True}
        '''
        try:
            #.one() ensures that there would be just one user with that email.
            # Although database should prevent that from happening -
            # lets make it buletproof
            user = Session.query(cls).filter_by(email=data['email']).one()
        except NoResultFound:
            user = cls(
                    email=data['email'],
                    username=data['given_name'],
                )
            Session.add(user)
            Session.commit()
        return user

    def is_active(self):
        return True

    def is_authenticated(self):
        """
        Returns `True`. User is always authenticated. Herp Derp.
        """
        return True

    def is_anonymous(self):
        """
        Returns `False`. There are no Anonymous here.
        """
        return False

    def get_id(self):
        """
        Assuming that the user object has an `id` attribute, this will take
        that and convert it to `unicode`.
        """
        try:
            return unicode(self.user_id)
        except AttributeError:
            raise NotImplementedError("No `id` attribute - override get_id")

    def __eq__(self, other):
        """
        Checks the equality of two `UserMixin` objects using `get_id`.
        """
        if isinstance(other, UserMixin):
            return self.get_id() == other.get_id()
        return NotImplemented

    def __ne__(self, other):
        """
        Checks the inequality of two `UserMixin` objects using `get_id`.
        """
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal    

class ExampleModel(ndb.Model):
    """Example Model"""
    example_name = ndb.StringProperty(required=True)
    example_description = ndb.TextProperty(required=True)
    added_by = ndb.UserProperty()
    timestamp = ndb.DateTimeProperty(auto_now_add=True)
