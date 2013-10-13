#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import logging
import jinja2
import json
import urllib
import urllib2
import webapp2
from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import datastore_errors
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers

try:
  # When deployed
  from google.appengine.runtime import OverQuotaError
except ImportError:
  # In the development server
  from google.appengine.runtime.apiproxy_errors import OverQuotaError

from utils import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class BaseHandler(webapp2.RequestHandler):
    '''Parent class for all handlers, shortens functions'''
    def write(self, content):
        return self.response.out.write(content)

    def rget(self, name):
        '''Gets a HTTP parameter'''
        return self.request.get(name)

    def logged_in(self, email_cookie = None):
        '''Checks if login cookie is valid (authenticates user)'''
        email_cookie = self.request.cookies.get(LOGIN_COOKIE_NAME, '')
        if email_cookie:
            email, hashed_email = email.split("|")
            if email and hashed_email and hash_str(email) == hashed_email:
                return True
            else:
                self.delete_cookie(LOGIN_COOKIE_NAME)
                return False
        return False

class MainHandler(BaseHandler):
    def get(self):
        self.write("hi david")

class Picture(db.Model):
    picture = db.TextPropertyy(required = True)
    # location = db.StringProperty(required=True)
    latitude = db.FloatProperty(required=True)
    longitude = db.FloatProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)

class Image(BaseHandler):
    def get(self):
        self.write('i hate blobstore')
    def post(self):
        picture = self.rget('picture')
        #location = self.rget('location')
        latitude, longitude = coords.split(',')
        p = Picture(picture=picture,latitude=latitude,longitude=longitude)
        p.put()

class CreateAccount(BaseHandler):
    def post(self):
        username = self.rget('username')
        psswrd = self.rget('password')
        verify = self.rget('verify')
        email = self.rget('email')
        self.response.headers['Content-Type'] = 'application/json'
        returned = create_account(username=username, password=psswrd, verify=verify, email=email)
        if 'cookie' in returned:
            self.response.headers.add_header('Set-Cookie', returned['cookie'])
        del returned['cookie']
        self.write(json.dumps(returned))

class GetFeed(BaseHandler):
	def get(self):
		coords = self.rget('coords')
		latitude, longitude = coords.split('|')
		latitude = float(latitude)
		longitude = float(longitude)
		url = "http://maps.googleapis.com/maps/api/geocode/json?latlng=%s&sensor=false" % (str(latitude) + "," + str(longitude))
		response = urllib2.urlopen(url)
		html = json.load(response)
		city_name = html['results'][0]['address_components'][2]['long_name']
		get_feed_by_city(city_name)

app = webapp2.WSGIApplication([('/', MainHandler),
                                ('/create_account', CreateAccount),
                               ('/get_feed', GetFeed),
                                ('/image',Image),],
                              debug=True)
