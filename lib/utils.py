import re
import hashlib
import random
import hmac
import string

RE_USER = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_user(username):
	return username and RE_USER.match(username)

RE_PASSWORD = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_password(password):
	return password and RE_PASSWORD.match(password)

RE_EMAIL = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or RE_EMAIL.match(email)



def create_salt(lenght=5):
	return "".join(random.choice(string.hexdigits) for x in range(lenght) )



def pw_hashing(username, password, salt = None):
	if salt == None:
		salt = create_salt()
	hash= hashlib.sha256(username+password+salt).hexdigest()
	return '%s|%s' % (hash, salt) 

def check_pw(username, password, user_hash):
	if user_hash:
		pw_hash,salt = user_hash.split("|")
		calc_hash = pw_hashing(username, password, salt)
		if user_hash == calc_hash:
			return True
	else:
		return False



SECRET = 'Prelouc'
def hash_cookie(value):
	cookie_hash = hmac.new(SECRET,value).hexdigest()
	return "%s|%s" %(value, cookie_hash)



def check_cookie(hashed_cookie):
	value, unused_hash = hashed_cookie.split("|")
	if hash_cookie(value) == hashed_cookie:
		return value
	else:
		return False

