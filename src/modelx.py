# -*- coding: utf-8 -*-

from google.appengine.ext import ndb
import md5
import util


class BaseX(object):
  @classmethod
  def retrieve_one_by(cls, name, value):
    cls_db_list = cls.query(getattr(cls, name) == value).fetch(1)
    if cls_db_list:
      return cls_db_list[0]
    return None


class ConfigX(object):
  @classmethod
  def get_master_db(cls):
    return cls.get_or_insert('master')

class UserX(object):
  @classmethod
  @property

  def get_master_db(cls):
    return cls.get_or_insert('master')
    
  def avatar_url(self):
    return 'http://www.gravatar.com/avatar/%s?d=identicon&r=x' % (
        md5.new(self.email or self.name).hexdigest().lower()
      )

class FollowersX(object):
  @classmethod
  @property

  def get_master_db(cls):
    return cls.get_or_insert('master')

class InboxX(object):
  @classmethod
  @property

  def get_master_db(cls):
    return cls.get_or_insert('master')

class SentX(object):
  @classmethod
  @property

  def get_master_db(cls):
    return cls.get_or_insert('master')


class EventX(object):
  @classmethod
  def get_master_db(cls):
      return cls.get_or_insert('master')


class TeamX(object):
  @classmethod
  def get_master_db(cls):
      return cls.get_or_insert('master')

class ConfWorkX(object):
  @classmethod
  def get_master_db(cls):
      return cls.get_or_insert('master')

class TeamRegisterX(object):
  @classmethod
  def get_master_db(cls):
      return cls.get_or_insert('master')

class SubEventX(object):
  @classmethod
  def get_master_db(cls):
      return cls.get_or_insert('master')

class TeamMembersX(object):
  @classmethod
  def get_master_db(cls):
      return cls.get_or_insert('master')

