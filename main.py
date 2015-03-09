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
import webapp2
import jinja2
import os
import time
import re

import hmac
import hashlib
import random
from string import letters

from google.appengine.ext import db 
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
							   autoescape=False)

#PAGE_RE = r'/\w*' #  r'(/(?:[a-zA-Z0-9_-]+/?)*)'
PAGE_RE = r'/[\w+/?]+'

#  Regular Expressions for Sign up and login forms
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)



class MainHandler(webapp2.RequestHandler):
	def get(self):
		self.redirect("/WikiPage")

	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render(self, template, **kw):
		self.write(render_str(template, **kw))


class WikiPage(MainHandler):
	def get(self):
		pg_path = self.request.path
		# pagename = pg_path.split('/')[1]
		pagename = pg_path[1:]
		page_content = None
		print "=="*20
		print "pagename: %s, pg_path: %s" % (pagename, pg_path)
		page_version = self.request.query_string
		if page_version:
			page_content = self.render_history_version(page_version, pagename)
			self.render("viewMode.html", new_content=page_content)



		cookie_val = self.request.cookies.get('user_id')
		logged_in = check_if_logged_in(cookie_val)
		print "LOGGED IN?: %s" % logged_in

		print "=="*20
		if not page_content:
			if check_cache(pagename):
				page_content = cache_input(pagename)
				if logged_in:
					self.render("viewMode.html", path='/_edit'+pg_path, link_name="edit", new_content=page_content,
								status="/logout", link_status="logout", history_link='/_history'+pg_path)  #  need to put history for the rest.
				else:
					pg_path = '/signup'
					self.render("viewMode.html", path=pg_path, link_name="signup", new_content=page_content,
								status="/login", link_status="login")
			else:
				page_content = try_page_db(pagename)
				if page_content:
					if logged_in:
						self.render("viewMode.html", path='/_edit'+pg_path, link_name="edit", new_content=page_content,
									status="/logout", link_status="logout")
					else:
						pg_path = '/signup'
						self.render("viewMode.html", path=pg_path, link_name="signup", new_content=page_content,
									status="/login", link_status="login")
				else:
					if logged_in:
						self.redirect(('/_edit%s' % pg_path))
					else:
						self.redirect('/signup')

 	def render_history_version(self, version, path):
 		v_num = int(version.split('=')[-1])
 		print "the path: %s, the v: %s" % (path, v_num)
 		pages = db.GqlQuery("SELECT * FROM Pages " +
 							"WHERE page_name = :1 " +
 							"ORDER by page_date_edited DESC ", path)
 		page_version = pages[v_num].page_content
 		return page_version


def check_if_logged_in(cookie_val):
	val = cookie_val.split('|')[0]
	if cookie_val == make_secure_val(val):
		return True
	else:
		return False



def check_cache(pagename):
	key = pagename
	page_content = memcache.get(key)
	print page_content
	if page_content:
		return True
	return False

def try_page_db(path):
	print "*"*20
	print "try page db before: %s" % path
	pages = db.GqlQuery("SELECT * FROM Pages " +
						"WHERE page_name = :1 " 
						"ORDER by page_date_edited DESC ", path).get()

	print "try page db after: %s" % pages
	if pages:
		key = path
		memcache.set(key, pages.page_content)
		return pages.page_content
	else:
		return False


def cache_input(pagename, update=False):
	key = pagename
	page_content = memcache.get(key)
	if page_content is None or update:
		pages = db.GqlQuery("SELECT * FROM Pages " +
							"WHERE page_name = :1 "
							"ORDER by page_date_edited DESC ", pagename) # need to figure out how to sort for newest entry.
		print "cache_input : % s" % pages[0].page_content
		page_content = pages[0].page_content
		memcache.set(key, pages[0].page_content)

	return page_content

class EditPage(MainHandler):

	def get(self, page_version=None):
		prev_path = self.get_prev_path()
		page_version = self.request.query_string
		print "PREV_PATH: %s, query: %s" % (prev_path, page_version)
		print prev_path[1:]
		#pagename = prev_path.split('/')[1]
		pagename = prev_path[1:]
		if pagename[-1] == '/':
			pagename = pagename[:-1]
			

		if page_version:
			print "NEW PAGENAME: %s " % pagename
			pages = db.GqlQuery("SELECT * FROM Pages " +
								"WHERE page_name = :1 " 
								"ORDER by page_date_edited DESC ", pagename)
			print "H"*20
			v_num = int(page_version.split('=')[-1])
			print "ENTITIY KEY: %s" % pages[v_num].key()
			version_key = pages[v_num].key()
			self.response.headers.add_header('set-cookie', '%s=%s; Path=/' % ('history_version', version_key))

			original_content = pages[v_num].page_content

			print original_content
			self.render("editMode.html", path=prev_path, original_content=original_content, status="/logout",
						link_status="logout")


		elif check_cache(pagename):
			original_content = cache_input(prev_path.split('/')[1])
			self.render("editMode.html", path=prev_path, original_content=original_content, status="/logout",
						link_status="logout")
		else:
			self.render("editMode.html", path=prev_path, status="/logout", link_status="logout")

	def post(self):
		page_version = self.request.query_string
		prev_path = self.get_prev_path()

		if prev_path[-1] == '/':
			prev_path = prev_path[:-1]


		if page_version:
			page_key = self.request.cookies.get('history_version')
			print "POSTING NEW HISTORY EDIT: %s" % Pages.get(page_key)
			page = Pages.get(page_key)
			page.page_content = self.request.get('content')
			page.put()
			time.sleep(1)
			self.redirect('/_history'+prev_path)
		else:
			page_name = prev_path[1:]
			page = Pages(page_name=page_name)
			new_content = self.request.get('content')
			page.page_content = new_content

			page.put()
			time.sleep(1)

			cache_input(page_name, update=True)
			time.sleep(1)
			print "*"*20
			self.redirect(prev_path)
		# self.render("viewMode.html", new_content=new_content)

	def get_prev_path(self):
		prev_path = self.request.path
		prev_path = prev_path.split('/_edit')
		prev_path = ''.join(prev_path)

		return prev_path


# store all wiki pages
class Pages(db.Model):
	page_name = db.StringProperty(required=True)
	page_content = db.TextProperty()
	page_date_edited = db.DateTimeProperty(auto_now_add=True)


# store all users info
class User(db.Model):
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def login(cls, name, pw):
		u = User.all().filter('name =', name).get()
		if u:
			if valid_pw(name, pw, u.pw_hash):
				return True
		else:
			return False



SECRET = 'supersecret'
def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())


def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s,%s" % (salt, h)


# make sure okay at login
def valid_pw(name, pw, h):
	salt = h.split(',')[0]
	if h == make_pw_hash(name, pw, salt):
		return True
	else:
		return False



class Signup(MainHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')

		params = dict(username=self.username)

		check_error = False
		if not valid_username(self.username):
			params['error_username'] = "Not a valid username"
			check_error = True
		if not valid_password(self.password):
			params['error_password'] = "Not a valid password"
			check_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Passwords do not match"
			check_error =  True

		if check_error:
			self.render("signup.html", **params)
		else:
			if not self.check_user_exists():
				time.sleep(1)
				u = User.by_name(self.username)
				cookie_val = make_secure_val(str(u.key().id()))
				self.response.headers.add_header('set-cookie', '%s=%s; Path=/' % ('user_id', cookie_val))

				self.redirect('/WikiPage')

	def check_user_exists(self):
		u = User.by_name(self.username)
		if u:
			err_msg = "Sorry, that user is not available"
			self.render("signup.html", error_username=err_msg)
			return True
		else:
			password = make_pw_hash(self.username, self.password)
			u = User(name=self.username, pw_hash=password)
			u.put()
			return False

class Login(MainHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		if User.login(username, password):
			u = User.by_name(username)
			cookie_val = make_secure_val(str(u.key().id()))
			self.response.headers.add_header('set-cookie', '%s=%s; Path=/' % ('user_id', cookie_val))
			self.redirect('/WikiPage')
		else:
			err_msg = "Sorry, that was not valid"
			self.render("login.html", error_password=err_msg)


class Logout(MainHandler):
	def get(self):
		self.response.headers.add_header('set-cookie', 'user_id=; Path=/')
		self.redirect('/login')


class History(MainHandler):
	def get(self):
		path = self.request.path
		#path = path.split('/')[-1]
		path = path[10:]
		print "WikiPage History: %s" % path
		pages = db.GqlQuery("SELECT * FROM Pages " +
							"WHERE page_name = :1 " 
							"ORDER by page_date_edited DESC ", path)

		print "*"*20
		print "HIStORY"
		self.render("history.html", history=pages, view_link=path, edit_link="/_edit/"+path)



app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/signup', Signup),
	('/login', Login),
	('/logout', Logout),
	('/_history' + PAGE_RE, History),
	('/_edit' + PAGE_RE, EditPage),
	(PAGE_RE, WikiPage),
], debug=True)
