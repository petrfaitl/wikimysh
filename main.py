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
import webapp2
import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
import logging
from lib.utils import valid_user, valid_password, valid_email, pw_hashing, check_pw,hash_cookie, check_cookie
import datetime
import hmac


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	def render_str(self, template, **params):
		#params['user'] = self.logged_user
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, value):
		uid = hash_cookie(value)
		Expires = (datetime.datetime.now() + datetime.timedelta(weeks=8)).strftime('%a, %d %b %Y %H:%M:%S GMT')
		self.response.headers.add_header("Set-Cookie", '%s = %s; Domain = wikimysh.appspot.com;  Path= /; Expires= %s' %(name,uid, Expires)) #Domain = wikimysh.appspot.com;
	
	def clear_cookie(self,name):
		self.response.headers.add_header("Set-Cookie", '%s =; Domain = wikimysh.appspot.com; Path= /' % name) #Domain = wikimysh.appspot.com;

	def read_secure_cookie(self, name):
		secure_val = self.request.cookies.get(name)
		if not secure_val:
			return False
		verified_uid = check_cookie(secure_val)
		if secure_val and verified_uid:
			return verified_uid


	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('uid')
		if not uid:
			self.logged = None
			return None
		user = memcache_user_id(uid)
		if uid and user:
			self.logged = uid
			self.logged_user = user.username
		else:
			self.logged = None




user_auth = {'signup':{"url":"/signup","title": "Signup"},
			'login':{"url":"/login","title": "Login"},
			'logout':{"url":"/logout","title": "Logout"}}




class USERS(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	user_created = db.DateTimeProperty(auto_now = True)


	@classmethod
	def register(cls, username, password, email = None):
		password_hash = pw_hashing(username, password)
		return USERS(username = username, password_hash = password_hash, email = email)


		


def memcache_user(username = 'default', source = None, update = False ):
	key = username
	cache = memcache.get(key)
	if not cache or update == True:
		logging.error("DB_QUERY")
		u = USERS.all()
		u.filter('username =', username)
		cache = u.get()
		
		memcache.set(key,cache)
		return cache
	else:
		return cache


def memcache_user_id(uid, update = False):
	key = str(uid)
	cache = memcache.get(key)
	if not cache or update:
		cache = USERS.get_by_id(int(uid))
		
		memcache.set(key, cache)
		return cache
	else:
		return cache



class Wikidb(db.Model):
	url = db.StringProperty(required =True)
	content =db.StringProperty(multiline = True)
	created = db.DateTimeProperty()
	created_by = db.StringProperty()
	last_edit = db.DateTimeProperty()
	last_edit_by = db.StringProperty()


	def html_content(self):
	# Escape, then convert newlines to br tags, then wrap with Markup object
	# so that the <br> tags don't get escaped.
		return jinja2.Markup(self.content.replace('\n', '<br>'))

	@classmethod
	def new_wiki(cls, url, content, logged_user):
		return Wikidb(url = url, content = content, created_by = logged_user, last_edit_by = logged_user)
	
	@classmethod
	def by_page_url(cls,url):
		page_content = Wikidb.all().filter("url =", url).order('-last_edit').get()
		return page_content

	@classmethod
	def by_page_url_multi(cls,url):
		page_content = Wikidb.all().filter("url =", url).order('-last_edit').run(limit=100)
		return page_content

	@classmethod
	def by_page_id(cls,page_id):
		page_content = Wikidb.get_by_id(int(page_id))
		return page_content

####User auth

class Signup(Handler):
	def get(self):


		self.render("signup.html", user_auth = user_auth)

	def post(self):
		referer = self.request.referer
		has_error = False
		username = self.request.get("username")
		password = self.request.get("password")
		password_verify = self.request.get("verify")
		email = self.request.get("email")

		params=dict(username=username, email=email)

		if not valid_user(username):
			params['error_username'] = "Choose different username. Use 3-20 chars, lowercase, uppercase only. No spaces."
			has_error = True

		if not valid_password(password):
			params['error_password'] = "Your password is invalid."
			has_error =True
		
		if password_verify != password:
			params['error_verify'] = "Your passwords do not match."
			has_error =True
		
		if not valid_email(email):
			params['error_email'] = "Something seems to be wrong. Check your email address."
			has_error = True
			


		if has_error == True:
			self.render("signup.html", **params)
		else:
			if memcache_user(username = username) == None:
				u = USERS.register(username,password,email)
				u.put()
				memcache_user(update = True)
				self.set_secure_cookie('uid',str(u.key().id()))

				self.redirect("/")
			else:
				params['error_username'] = "User already exists"
				self.render("signup.html", **params)


		

class Login(Handler):
	def get(self):
		self.render("login.html", user_auth = user_auth )

	def post(self):

		username = self.request.get('username')
		password = self.request.get('password')

		params= dict(username = username)

		if valid_user(username):
			u= memcache_user(username = username)
			if u and check_pw(username, password, u.password_hash):
				self.set_secure_cookie('uid',str(u.key().id()))
				# if not 'login'  in referer:
				# 	self.redirect(referer)
				# else:
				self.redirect("/")
			else:
				
				self.render("login.html", user_auth = user_auth, login_error = "Invalid login")

class Logout(Handler):
	def get(self):
		referer = self.request.referer
		self.clear_cookie('uid')
		if referer:
			self.redirect(referer)
		else:
			self.redirect('/')

##### Wiki management

#duplicated code for main page

# class MainHandler(Handler):

# 	def get(self):
# 		url = self.request.path #get page url
		
# 		wiki_post = memcache_wiki(url)
# 		self.render("wiki.html", wiki_post = wiki_post)




def memcache_wiki(url, update = False):
	key = url
	wiki_post = memcache.get(key)
	if not wiki_post or update:
		
		wiki_post = Wikidb.by_page_url(str(url))
		memcache.set(key, wiki_post)
		return wiki_post
	else:
		return wiki_post



class WikiPage(Handler):
	def get(self, url = None):
		logged_usr = ''
		if self.logged:
			logged_usr = self.logged_user
		url = self.request.path
		page_id = self.request.query_string
		if url == '/_edit':
			self.redirect('/_edit/')
		if page_id:
			wiki_post = Wikidb.by_page_id(page_id[3:])
		else:
			wiki_post = memcache_wiki(url)
		if wiki_post:
			self.render('wiki.html', wiki_post = wiki_post, username = logged_usr, url = url, page_id = '?'+page_id)
		else:
			self.redirect('/_edit%s' %url)


class EditPage(Handler):


	def get(self,url):
		page_id = self.request.query_string
		path = self.request.path
		if page_id:
			wiki_post = Wikidb.by_page_id(page_id[3:])
		else:
			wiki_post = Wikidb.by_page_url(str(url))
		if self.logged:
			logged_usr = self.logged_user
			self.render("edit_wiki.html", wiki_post = wiki_post, username = logged_usr, path = path, url = url, page_id = '')
		else:
			logged_usr = None
			self.render('wiki.html', wiki_post = wiki_post, username = logged_usr, url = url)
	
	def post(self,url):
		content = self.request.get("content")
		logged_usr = self.logged_user
		wiki_post = memcache_wiki(url)
		if False: # wiki_post
			wiki_post.content = content
			wiki_post.last_edit_by = logged_usr
			wiki_post.last_edit = datetime.datetime.now()
			wiki_post.put()
			memcache_wiki(url, update = True)
		else:
			w = Wikidb.new_wiki(str(url),content,logged_usr)
			w.created =w.last_edit= datetime.datetime.now()
			
			w.put()
			memcache_wiki(url, update = True)
		self.redirect('%s' %str(url))

class HistoryPage(Handler):
	def get(self, url):
		logged_usr = ''
		if self.logged:
			logged_usr = self.logged_user
		wiki_post = Wikidb.by_page_url_multi(str(url))
		self.render("history_wiki.html", wiki_post = wiki_post, username = logged_usr, url = url)



PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
							('/', WikiPage),
							('/signup', Signup),
							('/login', Login),
							('/logout', Logout),
							('/_edit' + PAGE_RE, EditPage),
							('/_history' + PAGE_RE, HistoryPage),
							(PAGE_RE, WikiPage),
							],
							debug=True)



