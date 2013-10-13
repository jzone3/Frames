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

class MainHandler(webapp2.RequestHandler):
  def get(self):
    upload_url = blobstore.create_upload_url('/upload')
    self.response.out.write('<html><body>')
    self.response.out.write('<form action="%s" method="POST" enctype="multipart/form-data">' % upload_url)
    self.response.out.write("""Upload File: <input type="file" name="file"><br> <input type="submit"
        name="submit" value="Submit"> </form></body></html>""")

class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
  def post(self):
    upload_files = self.get_uploads('file')  # 'file' is file upload field in the form
    blob_info = upload_files[0]
    self.redirect('/serve/%s' % blob_info.key())

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
  def get(self, resource):
    resource = str(urllib.unquote(resource))
    blob_info = blobstore.BlobInfo.get(resource)
    self.send_blob(blob_info)

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


app = webapp2.WSGIApplication([('/', MainHandler),
                                ('/create_account', CreateAccount),
                               ('/upload', UploadHandler),
                               ('/serve/([^/]+)?', ServeHandler)],
                              debug=True)
