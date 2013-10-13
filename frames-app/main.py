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
import webapp2
from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import datastore_errors

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

class MainHandler(BaseHandler):
    def get(self):
        self.response.write('Hello world!')

class SendImage(BaseHandler):
    def get(self):
        self.response.write('Hello world!')

class CreateAccount(BaseHandler):
    def post(self):
    	username = self.rget('username')
    	psswrd = self.rget('psswrd')
    	verify = self.rget('verify')
    	email = self.rget('email')
    	self.response.headers['Content-Type'] = 'application/json'
        return json.dumps(create_account(username, psswrd, verify, email))

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/send_image', SendImage)
], debug=True)
