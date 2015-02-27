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

from google.appengine.ext import db 
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
							   autoescape=False)

PAGE_RE = r'/\w*' #  r'(/(?:[a-zA-Z0-9_-]+/?)*)'


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
		print pg_path
		self.render("viewMode.html", path=pg_path)

  	def post(self):
  		pg_path = self.request.path
  		self.redirect(('/_edit%s' % pg_path))


def cache_input(pagename, update=False):
	key = pagename
	page_content = memcache.get(key)
	if page_content is None or c:
		pages = db.GqlQuery("SELECT * FROM Pages "
							"WHERE page_name = :1", pagename)

		
		print "*"*20
		print pages[0].page_content
		#memcache.set(key, pages.page_content)

	return page_content

class EditPage(MainHandler):

	def get(self):
		prev_path = self.get_prev_path()
		self.render("editMode.html", path=prev_path)

	def post(self):
		prev_path = self.get_prev_path()
		page_name = prev_path.split('/')[1]
		page = Pages(page_name=page_name)
		new_content = self.request.get('content')
		page.page_content = new_content

		page.put()
		time.sleep(2)

		cache_input(page_name, update=True)
		print "*"*20
		self.redirect(prev_path)
		# self.render("viewMode.html", new_content=new_content)

	def get_prev_path(self):
		prev_path = self.request.path
		prev_path = prev_path.split('/_edit')
		prev_path = ''.join(prev_path)

		return prev_path

class Pages(db.Model):
	page_name = db.StringProperty(required=True)
	page_content = db.TextProperty()








app = webapp2.WSGIApplication([
	('/', MainHandler),
	(PAGE_RE, WikiPage),
	('/_edit' + PAGE_RE, EditPage)
], debug=True)
