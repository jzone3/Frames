from google.appengine.ext import db
from google.appengine.api import datastore_errors
import re
import json
import hmac
import hashlib
import urllib2
import datetime
import random
import string
import logging

from secret import *

try:
  # When deployed
  from google.appengine.runtime import OverQuotaError
except ImportError:
  # In the development server
  from google.appengine.runtime.apiproxy_errors import OverQuotaError

LOGIN_COOKIE_NAME = 'login_cookie'

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")

# class Email_Verification(db.Model):
# 	email          = db.StringProperty(required = True)
# 	date_created   = db.DateTimeProperty(auto_now_add = True)

class Picture(db.Model):
	picture = db.TextProperty(required = True)
	# location = db.StringProperty(required=True)
	latitude = db.FloatProperty(required=True)
	longitude = db.FloatProperty(required=True)
	created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
	email          = db.StringProperty(required = True)
	username       = db.StringProperty(required = True)
	password       = db.StringProperty(required = True)
	date_created   = db.DateTimeProperty(auto_now_add = True)
	# email_verified = db.BooleanProperty(required = True)

RADIUS_INCREMENTS = [5, 10, 25, 50, 100]

GET_USER = db.GqlQuery("SELECT * FROM Users WHERE email = :email LIMIT 1")

def get_feed_by_coords(latitude, longitude):
	#(x - h)^2 + (y - k)^2 = r²
	r = None
	for d in RADIUS_INCREMENTS:
		lat_plus = latitude + d
		lat_minus = latitude - d
		lon_plus = longitude + d
		lon_minus = longitude - d
		r = (db.GqlQuery("SELECT * FROM Picture WHERE latitude > :lat_minus AND \
													 latitude < :lat_plus AND \
													 longitude > :lon_minus AND \
													 longitude < :lon_plus", lat_minus = lat_minus, lat_plus = lat_plus, lon_minus = lon_minus, lon_plus = lon_plus)).get()
		if r and len(r) > 7:
			break
	return r4


def get_city_by_coords(latitude, longitude):
	# latitude, longitude = coords.split('|')
	latitude = float(latitude)
	longitude = float(longitude)
	url = "http://maps.googleapis.com/maps/api/geocode/json?latlng=%s&sensor=false" % (str(latitude) + "," + str(longitude))
	response = urllib2.urlopen(url)
	html = json.load(response)
	city_name = html['results'][0]['address_components'][2]['long_name']
	return city_name

def hash_str(string):
	'''Hashes a string for user cookie'''
	return hmac.new(SECRET, str(string), hashlib.sha512).hexdigest()

def salted_hash(password, salt):
	'''Hashes a string for user password'''
	return hashlib.sha256(password + salt).hexdigest()

def make_salt():
	'''Makes random salt for user cookie'''
	return ''.join(random.choice(string.letters) for x in xrange(5))

def unique_email(email):
	'''Checks that an email is not taken already'''
	accounts = (db.GqlQuery("SELECT * FROM Users WHERE email = :email", email = email)).get()
	if accounts is None:
		return True
	return False

def get_user(email):
	'''Get User object from email'''
	GET_USER.bind(email = email)
	user = GET_USER.get()

	return user

def check_login(email, password):
	"""Checks if login info is correct

	Returns:
		[False, error text]
		OR
		[True, cookie]
	"""

	correct = False

	if email != '' and password != '':		
		accounts = memcache.get('user-'+email)
		logging.info("DB LOGIN check_login(): "+email)
		GET_USER.bind(email = email)
		accounts = GET_USER.get()

		if accounts is None:
			return [False, 'email does not exist']

		(db_password, salt) = (accounts.password).split("|")

		if salted_hash(password, salt) == db_password:
			return [True, '%s=%s|%s;' % (LOGIN_COOKIE_NAME, str(email), str(hash_str(email)))]

	return [False, 'Invalid email or password!']

# def change_email(previous_email, new_email):
# 	"""
# 	Changes a user's email
# 	Returns:
# 		[Success_bool, error]
# 	"""
# 	if new_email == '':
# 		return [False, 'No email entered']
# 	if not EMAIL_RE.match(new_email + "@bergen.org"):
# 		return [False, "That's not a valid email."]

# 	user = get_user(previous_email)
# 	user.email = new_email
# 	user.email_verified = False
# 	memcache.set('user-'+new_email, user)
# 	user.put()
# 	email_verification(new_email, user.name)
# 	return [True]

# def change_password(old, new, verify, email):
# 	'''Change a user's password'''
# 	if new == '':
# 		return [False, {'new_password_error' : "Enter a password"}]
# 	if old == '':
# 		return [False, {'password_error' : "Enter your current password"}]
# 	elif not PASS_RE.match(new):
# 		return [False, {'new_password_error' : "That's not a valid password."}]
# 	elif verify == '':
# 		return [False, {'verify_password_error' : "Verify your password"}]
# 	elif verify != new:
# 		return [False, {'verify_password_error' : "Your passwords didn't match."}]
# 	if not check_login(email, old)[0]:
# 		return [False, {'password_error' : "Incorrect password."}]

# 	user = get_user(email)
# 	(db_password, db_salt) = (user.password).split("|")
# 	if salted_hash(old, db_salt) == db_password:		
# 		salt = make_salt()
# 		hashed = salted_hash(new, salt)
# 		hashed_pass = hashed + '|' + salt

# 		user.password = hashed_pass
# 		user.put()

# 		memcache.set('user-'+email, user)
# 		memcache.set('useremail-'+str(user.email), user)
# 		logging.info('CACHE set user-'+email)
# 		logging.info('CACHE set useremail-'+str(user.email))

# 		cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(email), hash_str(email), remember_me())
# 		return [True, cookie]
# 	else:
# 		return [False, {'current_password_error' : 'Incorrect current password'}]

# def get_verified(email):
# 	'''Gets email_verified from db from email'''
# 	return get_user(email, True).email_verified

def create_account(email='', password='', verify='', agree='', username=''):
	"""Signs up user

	Returns:
		Dictionary of elements with error messages and 'success' : False
		OR
		{'cookie' : cookie, 'success' : True}
	"""

	to_return = {'success' : False}

	if password == '':
		to_return['password'] = "Please enter a password"
	elif not PASS_RE.match(password):
		to_return['password'] = "That's not a valid password."
	elif verify == '':
		to_return['verify'] = "Please verify your password"
	elif verify != password:
		to_return['verify'] = "Your passwords didn't match."

	if username == '':
		to_return['username'] = "That is not a valid username."

	if not EMAIL_RE.match(email) and email != '':
		to_return['email'] = "That's not a valid email."
	elif not unique_email(email):
		to_return['email'] = "Email already exits!"

	# if agree != 'on':
	# 	to_return['agree'] = "You must agree to the Terms of Service to create an account"

	if len(to_return) == 1:
		salt = make_salt()
		hashed = salted_hash(password, salt)
		hashed_pass = hashed + '|' + salt

		account = Users(email = email, password = hashed_pass, username = username, email_verified = False)
		account.put()

		expiration = datetime.datetime.now() + datetime.timedelta(days=500)

		cookie = LOGIN_COOKIE_NAME + '=%s|%s; Expires=%s Path=/' % (str(email), hash_str(email), expiration.strftime("%a, %d-%b-%Y %H:%M:%S PST"))
		to_return['cookie'] = cookie
		to_return['success'] = True
		# email_verification(email, name)

	return to_return

# def email_verification(email, name):
# 	'''Sends a verification email for new user'''
	# link, dellink = get_unique_link(email)
	# body, html = make_activation_email(email, link, dellink, name)
	# try:
	# 	mail.send_mail(sender="ClassMatch <classmatch.verify@gmail.com>",
	# 					to="%s <%s>" % (name, email + "@bergen.org"),
	# 					subject="Email Verification",
	# 					body=body,
	# 					html=html)
	# except OverQuotaError:
	# 	return 

# def get_unique_link(email):
# 	'''Creates a verification link for new user'''
# 	reset_user_link(email)
# 	link_row = Email_Verification(email = email)
# 	link_row.put()
# 	return 'http://class-match.appspot.com/verify/' + str(link_row.key()), 'http://class-match.appspot.com/delete_email/' + str(link_row.key())

# def reset_user_link(email):
# 	'''Deletes email verification links for user'''
# 	links = db.GqlQuery("SELECT * FROM Email_Verification WHERE email = :email", email = email)
# 	for i in links:
# 		i.delete()

# def deleted(key):
# 	'''Wrong email, delete verficiation link'''
# 	link = db.get(key)
# 	if link is None:
# 		return False
# 	GET_USER.bind(email = link.email)
# 	user = GET_USER
# 	if user is None:
# 		return False
# 	memcache.delete(link.email + '_submitted')
# 	link.delete()
# 	for i in user:
# 		i.delete()
# 	return True

def delete_user_account(email):
	'''Deletes a user account and all related data'''
	GET_USER.bind(email = email)
	user = GET_USER.get()
	user.delete()

# def verify(key):
# 	'''Verfies email from verification link'''
# 	link = db.get(key)
# 	if link is None:
# 		return False
# 	if datetime.datetime.now() >= link.date_created + datetime.timedelta(hours=12):
# 		link.delete()
# 		return False
# 	user = get_user(link.email)
# 	if user is None:
# 		return False
# 	user.email_verified = True
# 	user.put()
# 	memcache.delete(link.email + '_submitted')
# 	memcache.delete('user-'+link.email)
# 	link.delete()
# 	return True

# def make_activation_email(email, link, ignore_link, name):
# 	html = """
# 	<!DOCTYPE HTML>
# 	<html>
# 	<head>
# 	<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
# 	</head>
# 	<body>
# 		Hi %s,<br/><br/>
# 		Thank you for visiting and joining <a href="http://class-match.appspot.com">ClassMatch</a>!<br/><br/><br/>
# 		To verify your email please click this link (or copy and paste it into your browser): <a href="%s">%s</a><br/><br/>
# 		If you did not make an account on ClassMatch click this link: <a href="%s">%s</a>
# 		<br/><br/><br/>
# 		NOTE: Links will expire in 12 hours
# 	</body>
# 	</html>
# 	""" % (name, link, link, ignore_link, ignore_link)
# 	logging.error([link,ignore_link])

# 	body = """Hi %s,
# 	Thank you for visiting and joining ClassMatch (http://class-match.appspot.com)!
# 	To verify your email please click this link (or copy and paste it into your browser): %s
# 	If you did not make an account on ClassMatch click this link: %s
# 	NOTE: Links will expire in 12 hours"""% (name, link, ignore_link)

# 	return body, html

