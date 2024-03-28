from flask import Flask, render_template, request, send_from_directory, send_file, flash, get_flashed_messages, redirect, url_for, session, make_response, jsonify, abort
from flask_cors import CORS, cross_origin
from flask_mysqldb import MySQL
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from pytube import extract
from pytube import Playlist
from pytube import YouTube
from concurrent.futures import ThreadPoolExecutor
import stripe
import secrets
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from jwt import encode as jwt_encode
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import timedelta
import time
import traceback
from flask_mail import Mail, Message
from youtube_transcript_api import YouTubeTranscriptApi
import MySQLdb.cursors, re, uuid, hashlib, datetime, os, math, urllib, json
import os
import shutil
from io import StringIO
from flask import Response
import csv
import jwt
import tiktoken
from fromvid import youtubefy
from sites import status_data
from sites import sitefy
from sites import get_domain_hyperlinks2
import random
import string
from langchain.callbacks import get_openai_callback
from utils import (
	parse_docx,
	parse_pdf,
	parse_txt,
	parse_csv,
	update_docs,
	search_docs,
	embed_docs,
	embed_docs2,
	text_to_docsv2,
	text_to_docs,
	get_answer,
	get_answer2,
	get_answer3,
	get_answer4,
	wrap_text_in_html,
)
from openai.error import OpenAIError
import pathlib
import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from pinecone import Pinecone

app = Flask(__name__)

CORS(app, resources={
    r"/appsumotoken/": {"origins": ['https://appsumo.com', 'http://appsumo.com']},
    r"/appsumonotification/": {"origins": ['https://appsumo.com', 'http://appsumo.com']},
    r"/api/v1/chatbot": {"origins": "*"},
    r"/get-bubble-placement": {"origins": "*"},
    r"/get-custom-color": {"origins": "*"},
    r"/*": {"origins": []}
}, supports_credentials=True)

# env variables
MYSQL_PASS = os.environ.get('MYSQL_PASSWORD')
STRIPE_API_KEY = os.environ.get('STRIPE_API_KEY')
PINECONE_API_KEY = os.environ.get('PINECONE_API_KEY')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
SECRET_APP_KEY = os.environ.get('SECRET_APP_KEY')


#JSON
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0" # to allow Http traffic for local dev
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
# initialize pinecone
# pinecone.init(
#     api_key=PINECONE_API_KEY,  # find at app.pinecone.io
#     environment="us-east-1-aws"  # next to api key in console
# )
pc = Pinecone(api_key=PINECONE_API_KEY)
print("Pinecone Initialized")


flow = Flow.from_client_secrets_file(
	client_secrets_file=client_secrets_file,
	scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
	redirect_uri="https://chatflux.io/callback"
)
# Upload settings
app.config["UPLOAD_FOLDER"] = "uploads/"
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "gif"}


app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['JSONIFY_MIMETYPE'] = 'application/json'

app.secret_key = SECRET_APP_KEY

# App Settings
app.config['threaded'] = True

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = MYSQL_PASS
app.config['MYSQL_DB'] = 'pythonlogin_advanced'
app.config['MYSQL_CHARSET'] = 'utf8mb4' 

# Enter your email server details below, the following details uses the gmail smtp server (requires gmail account)
app.config['MAIL_SERVER']= 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'jbmhstudio@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('SMTP_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = ('Chatflux.io','jbmhstudio@gmail.com')

# Enter your domain name below
app.config['DOMAIN'] = 'https://chatflux.io'

# Intialize MySQL
mysql = MySQL(app)

# Intialize Mail
mail = Mail(app)

# The list of roles
roles_list = ['Admin', 'Member']

# stripe.api_key = "sk_test_51Mo5qCKJEYYG9mCDHe7pD1hUNew9IbaXQpPwsod0JuCSMuJXdOVhRzjqMbqb4uKIYqd1mtfDhuSBTxZaGJAwDAbL00DpEOrC0V"
stripe.api_key = STRIPE_API_KEY

#------------ APPSUMO START ------------

myusername = "appsumoxchatflux"
mypassword = "#Ch4tflux#@@"
hashed_password = generate_password_hash(mypassword)
scrtky = 'Sum0xChFlx'

#TOKEN LINK : STEP 1
@app.route('/appsumotoken/', methods=['POST'])
def appsumotoken():
	
	username = request.form.get('username')
	password = request.form.get('password')

	if username == myusername and password == mypassword:
		token = uuid.uuid4()
		print(f"token : {token}")
		cursor = mysql.connection.cursor()
		cursor.execute('INSERT INTO appsumo_tokens (token) VALUES (%s)', (token,))
		mysql.connection.commit()
		cursor.close()
		return jsonify({"access": token}), 200
	
	else:
		print("wrong cred")
		return jsonify({'message': 'Invalid username or password'}), 403

#NOTIFICATION LINK
@app.route('/appsumonotification/', methods=['POST'])
def appsumonotification():

	print("Entering appsumonotification function...")
	start_time = time.time()
	action = request.form.get('action')
	print(f'ACTION DETECTED : {action}')
	plan_id = request.form.get('plan_id')
	uuid = request.form.get('uuid')
	activation_email = request.form.get('activation_email')
	print(f'Email : {activation_email} | plan_id : {plan_id} | uuid : {uuid} ')
	# Authorization check
	auth_header = request.headers.get('Authorization')
	if not auth_header or not auth_header.startswith('Bearer '):
		return jsonify({'message': 'Missing or invalid Authorization header'}), 403
	
	token = auth_header.split(' ')[1]
	print(f"Authorization token: {token}")

	# You can add more validation checks for data here if needed
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM appsumo_tokens WHERE token = %s ', (token,))
	# Fetch one record and return result
	token = cursor.fetchone()
	
	ourplan_id = appsumo2app(plan_id)
	print(f'our plan id : {ourplan_id}')

	if token:
		print("Token found in database -> filtering action now...")
		if action == "activate":
			invoice_item_uuid = request.form.get('invoice_item_uuid')
			cursor = mysql.connection.cursor()
			cursor.execute("UPDATE appsumo_tokens SET plan_id = %s, invoice_item_uuid = %s, uuid = %s, activation_email = %s WHERE token = %s", (ourplan_id, invoice_item_uuid, uuid, activation_email, token['token']))
			mysql.connection.commit()
			cursor.close()
			print("Product activated...")
			return jsonify({
				"message": "product activated",
				"redirect_url": f"https://chatflux.io/appsumoactivation?email={activation_email}&token={token['token']}"
			}), 201
		
		elif action == "enhance_tier":
			appsumo_update_account_plan(activation_email,ourplan_id)
			print("account updated")
			cursor = mysql.connection.cursor()
			cursor.execute("DELETE FROM appsumo_tokens WHERE token =%s and uuid IS NULL", (token['token'],))
			mysql.connection.commit()
			cursor = mysql.connection.cursor()
			cursor.execute("UPDATE appsumo_tokens SET plan_id = %s, token = %s  WHERE uuid = %s", (ourplan_id, token['token'], uuid))
			mysql.connection.commit()
			cursor.close()
			print("Product enhanced...")
			return jsonify({"message": "product enhanced"}), 200
		
		elif action == "reduce_tier":
			appsumo_update_account_plan(activation_email,ourplan_id)
			cursor = mysql.connection.cursor()
			cursor.execute("DELETE FROM appsumo_tokens WHERE token =%s and uuid IS NULL", (token['token'],))
			mysql.connection.commit()
			cursor = mysql.connection.cursor()
			cursor.execute("UPDATE appsumo_tokens SET plan_id = %s, token = %s WHERE uuid = %s", (ourplan_id, token['token'], uuid))
			mysql.connection.commit()
			cursor.close()
			print("Product reduced...")
			return jsonify({"message": "product reduced"}), 200
		
		elif action == "refund":
			revoke_plan(activation_email)
			invoice_item_uuid = request.form.get('invoice_item_uuid')
			cursor = mysql.connection.cursor()
			cursor.execute("DELETE FROM appsumo_tokens WHERE token =%s and uuid IS NULL", (token['token'],))
			mysql.connection.commit()
			cursor = mysql.connection.cursor()
			cursor.execute("UPDATE appsumo_tokens SET plan_id =	1, invoice_item_uuid = %s, token = %s, activation_email = %s WHERE uuid = %s", (invoice_item_uuid, token['token'], activation_email, uuid ))
			mysql.connection.commit()
			cursor.close()
			print("Product refunded...")
			return jsonify({"message": "product refunded"}), 200
		
		elif action == "update":
			invoice_item_uuid = request.form.get('invoice_item_uuid')
			print(f'invoice uuid : {invoice_item_uuid}')
			cursor = mysql.connection.cursor()
			cursor.execute("DELETE FROM appsumo_tokens WHERE token =%s and uuid IS NULL", (token['token'],))
			mysql.connection.commit()
			cursor.execute("UPDATE appsumo_tokens SET token =%s, plan_id =	%s, invoice_item_uuid = %s, activation_email = %s WHERE uuid = %s", (token['token'], ourplan_id, invoice_item_uuid, activation_email, uuid))
			mysql.connection.commit()
			cursor.close()
			print("Product updated...")
			return jsonify({"message": "product updated"}), 200

	else:
		print("Invalid token...")
		return jsonify({'message': 'Missing or invalid Authorization header'}), 403	
		# Default response for when no conditions are met
	return jsonify({'message': 'No action was performed'}), 400
	
		
@app.route('/appsumoactivate', methods=['POST'])
def appsumoactivate():
	
	email = request.args.get('email', default=None, type=str)
	token = request.args.get('token', default=None, type=str)
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve the settings
	settings = get_settings()
	# Retrieve the account with the email and reset code provided from the GET request
	cursor.execute('SELECT * FROM appsumo_tokens WHERE token = %s AND activation_email = %s AND active = 0', (token, email))
	tokenexist = cursor.fetchone()
	if tokenexist:
		if request.method == 'POST' and 'password' in request.form:
			user = email.split('@')
			username = user[0]+"-"+str(random.randint(10, 99))
			password = request.form['password']
			ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))

			# Retrieve the settings
			settings = get_settings()
			role = 'Member'
			# Hash the password
			hash = password + app.secret_key
			hash = hashlib.sha1(hash.encode())
			hashed_password = hash.hexdigest();
			# Check if account exists using MySQL
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
			account = cursor.fetchone()
			# reCAPTCHA
			if settings['recaptcha']['value'] == 'true':
				if 'g-recaptcha-response' not in request.form:
					msg= 'Invalid captcha!'
					flash(msg)
				req = urllib.request.Request('https://www.google.com/recaptcha/api/siteverify', urllib.parse.urlencode({ 'response': request.form['g-recaptcha-response'], 'secret': settings['recaptcha_secret_key']['value'] }).encode())	
				response_json = json.loads(urllib.request.urlopen(req).read().decode())
				if not response_json['success']:
					msg= 'Invalid captcha!'
			# Validation
			if account:
				msg= 'Account already exists!'
				flash(msg)
			elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
				msg= 'Invalid email address!'
				flash(msg)
			elif not password :
				msg= 'Please fill out the form!'
				flash(msg)
			elif len(password) < 5 or len(password) > 20:
				msg= 'Password must be between 5 and 20 characters long!'
				flash(msg)
			
			else:
				
				cursor = mysql.connection.cursor()
				cursor.execute("UPDATE appsumo_tokens SET  active = 1 WHERE token = %s", (token,))
				mysql.connection.commit()
				# Account doesnt exists and the form data is valid, now insert new account into accounts table
				cursor.execute('INSERT INTO accounts (username, plan_id ,password, email, activation_code, role, ip) VALUES (%s, %s, %s, %s, "activated", %s, %s)', (username, tokenexist['plan_id'], hashed_password, email, role, ip,))
				mysql.connection.commit()
				cursor.close()
				session['loggedin'] = True
				session['id'] = cursor.lastrowid
				session['username'] = username
				session['role'] = role

				#Remember me
				rememberme_code = username + email + app.secret_key
				rememberme_code = hashlib.sha1(rememberme_code.encode())
				rememberme_code = rememberme_code.hexdigest()
				# The cookie expires in 90 days
				expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
				resp = make_response(redirect(url_for('pricing')))
				resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
				# Update rememberme in accounts table to the cookie hash
				cursor = mysql.connection.cursor()
				cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, session['id'],))
				mysql.connection.commit()
				cursor.close()
				# Return response
				return resp
			
				# return redirect(url_for('profile'))
						
		elif request.method == 'POST':
			# Form is empty... (no POST data)
			msg = 'Please fill out the form!'

	else:
		msg='Unkown Token or Email'
	return render_template('appsumoactivate.html', email=email, token=token, msg=msg, settings=settings)
    
# proceed to redeem the appsumo license and activate account
@app.route('/appsumoactivation', methods=['GET', 'POST'])
def appsumoactivation():
	
	email = request.args.get('email', default=None, type=str)
	token = request.args.get('token', default=None, type=str)

	msg = ''
	# Retrieve the settings
	settings = get_settings()
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve the account with the email and reset code provided from the GET request
	cursor.execute('SELECT * FROM appsumo_tokens WHERE token = %s AND activation_email = %s AND active = 0', (token, email))
	token = cursor.fetchone()
	if token:
		print('token found indeed')
		msg = get_flashed_messages()
		msg = ', '.join(msg) if msg else ''  # join messages if there are any
		# Render registration form with message (if any)
		return render_template('appsumoactivate.html', email=email, token=token['token'], msg=msg, settings=settings)
	
	msg = 'Unknown Token or Email'
	return render_template('appsumoactivate.html', email=email, token=token, msg=msg, settings=settings)


#------------ APPSUMO END ------------


#------------ InnovAItors Partnership START ------------

# Step 1: Activation link 
@app.route('/innovaitorsactivation', methods=['GET', 'POST'])
def partner_register():
	ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
	# Redirect user to home page if logged-in
	if loggedin():
		return redirect(url_for('mychatbots'))
	# Output message variable
	msg = ''
	# Retrieve the settings
	settings = get_settings()
	# Check if "username", "password", "cpassword" and "email" POST requests exist (user submitted form)
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'cpassword' in request.form and 'email' in request.form:
		# Create variables for easy access
		username = request.form['username']
		password = request.form['password']
		cpassword = request.form['cpassword']
		email = request.form['email']
		role = 'Member'
		partner = 1
		# Hash the password
		hash = password + app.secret_key
		hash = hashlib.sha1(hash.encode())
		hashed_password = hash.hexdigest();
		# Check if account exists using MySQL
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
		account = cursor.fetchone()
		# reCAPTCHA
		if settings['recaptcha']['value'] == 'true':
			if 'g-recaptcha-response' not in request.form:
				return 'Invalid captcha!'
			req = urllib.request.Request('https://www.google.com/recaptcha/api/siteverify', urllib.parse.urlencode({ 'response': request.form['g-recaptcha-response'], 'secret': settings['recaptcha_secret_key']['value'] }).encode())	
			response_json = json.loads(urllib.request.urlopen(req).read().decode())
			if not response_json['success']:
				return 'Invalid captcha!'
		# Validation
		if account:
			return 'Account already exists!'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			return 'Invalid email address!'
		elif not re.match(r'^[A-Za-z0-9]+$', username):
			return 'Username must contain only alphanumeric characters!'
		elif not username or not password or not cpassword or not email:
			return 'Please fill out the form!'
		elif password != cpassword:
			return 'Passwords do not match!'
		elif len(username) < 5 or len(username) > 20:
			return 'Username must be between 5 and 20 characters long!'
		elif len(password) < 5 or len(password) > 20:
			return 'Password must be between 5 and 20 characters long!'
		elif settings['account_activation']['value'] == 'true':
			# Account activation enabled
			# Generate a random unique id for activation code
			activation_code = uuid.uuid4()
			# Insert account into database
			cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, partner, ip) VALUES (%s, %s, %s, %s, %s, %s, %s)', (username, hashed_password, email, activation_code, role, partner, ip,))
			mysql.connection.commit()
			# Create new message
			email_info = Message('Account Activation Required', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [email])
			# Activate Link URL
			activate_link = app.config['DOMAIN'] + url_for('activate', email=email, code=str(activation_code))
			# Define and render the activation email template
			email_info.body = render_template('activation-email-template.html', link=activate_link)
			email_info.html = render_template('activation-email-template.html', link=activate_link)
			# send activation email to user
			mail.send(email_info)
			# Output message
			return 'Please check your email to activate your account!'
		else:
			# Account doesnt exists and the form data is valid, now insert new account into accounts table
			cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, partner, ip) VALUES (%s, %s, %s, "activated", %s, %s, %s)', (username, hashed_password, email, role, partner, ip,))
			mysql.connection.commit()
			# Auto login if the setting is enabled
			if settings['auto_login_after_register']['value'] == 'true':
				session['loggedin'] = True
				session['id'] = cursor.lastrowid
				session['username'] = username
				session['role'] = role

				rememberme_code = username + email + app.secret_key
				rememberme_code = hashlib.sha1(rememberme_code.encode())
				rememberme_code = rememberme_code.hexdigest()
				# The cookie expires in 90 days
				expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
				resp = make_response(redirect(url_for('pricing')))
				resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
				# Update rememberme in accounts table to the cookie hash
				cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, session['id'],))
				mysql.connection.commit()
				cursor.close()
				session['partner'] = partner
				return 'autologin'
			# Output message
			return 'You have registered! You can now login!'
	elif request.method == 'POST':
		# Form is empty... (no POST data)
		return 'Please fill out the form!'
	# Render registration form with message (if any)
	return render_template('partner_register.html', msg=msg, settings=settings)

#------------ InnovAItors Partnership END ------------

@app.route('/terms/')
def termspage():
	return render_template('tos.html')

@app.route('/privacy/')
def privacypage():
	return render_template('privacy.html')

@app.route('/refund/')
def refundpage():
	return render_template('return.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(exception):
	app.logger.error(exception)
	sid = session['id']
	tb = traceback.format_exc()
	 
	# get current time in the desired format
	now = datetime.datetime.now()
	
	# get the request method (GET, POST etc) and the path
	method = request.method
	path = request.full_path
	
	# construct the line before traceback
	line_before_traceback = f"[{now}] ERROR in app: Exception on {path} [{method}]"
	
	email_info = Message('Chatflux.io - Internal Server Error', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = ['jbmhstudio@gmail.com'])
	email_info.body = f"User : {sid} - A 500 Internal Server Error has occurred in your Flask application.\n{line_before_traceback}\nHere is the error message: \n {str(exception)} \n\nHere is the traceback:\n{tb}"
	mail.send(email_info)
	return render_template('500.html'), 500

#SAVE CHATBOT GREETING
@app.route('/save_greeting', methods=['POST'])
def save_greeting():
	if not can_customize_greeting(session['id']):
		return jsonify({'status': 'error'}), 400
	data = request.get_json()
	greeting = data.get('greeting')
	chat_id = data.get('chatid')
	if greeting:
		save_greeting_to_db(greeting, chat_id)
		return jsonify({'status': 'success'})
	else:
		return jsonify({'status': 'error'}), 400
    
def save_greeting_to_db(greeting, chat_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE user_docs SET custom_greeting=%s WHERE chat_id=%s", (greeting, chat_id))
        mysql.connection.commit()
        cursor.close()
    except Exception as e:
        print(f"Error updating chatbot greeting: {e}")
	
#SAVE CHATBOT PROMPT
@app.route('/save_prompt', methods=['POST'])
def save_prompt():
	if not can_customize_prompt(session['id']):
		return jsonify({'status': 'error'}), 400
	data = request.get_json()
	prompt = data.get('prompt')
	chat_id = data.get('chatid')
	if prompt:
		save_prompt_to_db(prompt, chat_id)
		return jsonify({'status': 'success'})
	else:
		return jsonify({'status': 'error'}), 400
	
def save_prompt_to_db(prompt, chat_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE user_docs SET custom_prompt_base=%s WHERE chat_id=%s", (prompt, chat_id))
        mysql.connection.commit()
        cursor.close()
    except Exception as e:
        print(f"Error updating chatbot prompt: {e}")

#SAVE CHATBOT NAME
@app.route('/save_name', methods=['POST'])
def save_name():
    data = request.get_json()
    new_name = data.get('name')
    chat_id = data.get('chatid')
    if new_name:
        save_name_to_db(new_name, chat_id)
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error'}), 400
	
def save_name_to_db(name, chat_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE user_docs SET document_name=%s WHERE chat_id=%s", (name, chat_id))
        mysql.connection.commit()
        cursor.close()
    except Exception as e:
        print(f"Error updating chatbot name: {e}")
	

@app.route('/save_color', methods=['POST'])
def save_color():
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	data = request.get_json()
	color = data.get('color')
	chat_id = data.get('chatid')
	if color:
		save_color_to_db(color,chat_id)
		return jsonify({'status': 'success'})
	else:
		return jsonify({'status': 'error'}), 400
	
def save_color_to_db(color,chat_id):
	try:
		cursor = mysql.connection.cursor()
		cursor.execute("UPDATE user_docs SET custom_color=%s WHERE chat_id=%s", (color,chat_id))
		mysql.connection.commit()
		cursor.close()
	except Exception as e:
		print(f"Error updating color: {e}")


#Delete Chat
@app.route('/delete-chat', methods=['GET'])
def deletechat():
	chat_id = request.args.get('chatId', None)
	version = get_answerv(chat_id)

	if version == 2:
		print("Using Pinecone")
		chat_id = request.args.get('chatId', None)
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
		chatbot = cursor.fetchone()
		user_id = chatbot['user_id']
		if loggedin() and session['id'] == user_id:
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			# Delete account from database by the id get request param
			cursor.execute('DELETE FROM user_docs WHERE chat_id = %s', (chat_id,))
			mysql.connection.commit()

			# Remove the namspace 
			# index = pinecone.Index("index1")
			index = pc.Index("index1")
			namespace = chat_id
			# index.delete(deleteAll='true', namespace=namespace)
			index.delete(delete_all=True, namespace=namespace)
			print(f'Deleting {namespace}...')

			return jsonify({'status': 'success'})
		else:
			return jsonify({'status': 'error'})
	
	else:
		print("Using Chromadb")
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
		chatbot = cursor.fetchone()
		user_id = chatbot['user_id']
		if loggedin() and session['id'] == user_id:
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			# Delete account from database by the id get request param
			cursor.execute('DELETE FROM user_docs WHERE chat_id = %s', (chat_id,))
			mysql.connection.commit()
			# Remove the folder containing the chat file
			folder_path = f"doc/user_{chat_id}_doc_id"
			print(f'deleting -> {folder_path}')
			if os.path.exists(folder_path) and os.path.isdir(folder_path):
				shutil.rmtree(folder_path)
				print(f"ok deleted {chat_id}")
			return jsonify({'status': 'success'})
		else:
			return jsonify({'status': 'error'})
	
    
@app.route('/get-bubble-placement', methods=['GET'])
def get_chat_bubble_placement():
	chat_id = request.args.get('chatId', None)
	
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	mychatbot = cursor.fetchone()
	chat_bubble_placement = mychatbot['chat_bubble_placement']
	
	if mychatbot:
		return jsonify({"bubbleplacement": chat_bubble_placement})
	else:
		return jsonify({"error": "Invalid chat ID"})
	
	
	
	    
@app.route('/get-custom-color', methods=['GET'])
def get_custom_color():
	chat_id = request.args.get('chatId', None)
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	chatbot = cursor.fetchone()
	if chatbot:
		user_id = chatbot['user_id']
		if not can_customize_color(user_id):
			return jsonify({"error": "Your plan does not support customized chatbot appearance. Please consider upgrading to unlock this feature."})
		if chat_id:
			custom_color = get_color_from_db(chat_id)
			return jsonify({"color": custom_color})
	else:
		return jsonify({"error": "Invalid chat ID"})

def get_color_from_db(chat_id):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	mychatbot = cursor.fetchone()
	custom_color = mychatbot['custom_color']
	return custom_color

def stripe2app(sub_id):
	sub_ids = {
	'price_1Ov19iBWWWOdE1ao04rdKBuw':2,  # Adventurer (Monthly)
    'price_1Ov1B6BWWWOdE1aoH6dYugbz':3,  # Conqueror (Monthly)
    'price_1Ov1CnBWWWOdE1aoDykklTZh':4,  # The sky is the limit (Monthly)
    'price_1Ov1C6BWWWOdE1aoMiVpxTBo':2,  # Adventurer (Annually)
    'price_1Ov1BoBWWWOdE1ao8l9e677G':3,  # Conqueror (Annually)
    'price_1Ov1CQBWWWOdE1aoa2weav8Iweav8I':4,  # The sky is the limit (Annually)
	}
	plan_id=sub_ids.get(sub_id,'none')
	return plan_id

def appsumo2app(sub_id):
	sub_ids = {
	'chatflux_tier1':5,  # Adventurer (Monthly)
    'chatflux_tier2':6,  # Conqueror (Monthly)
    'chatflux_tier3':7,  # The sky is the limit (Monthly)
	}
	plan_id=sub_ids.get(sub_id,'none')
	return plan_id

price_idz = {
    '2': 'price_1Ov19iBWWWOdE1ao04rdKBuw',  # Adventurer (Monthly)
    '3': 'price_1Ov1B6BWWWOdE1aoH6dYugbz',  # Conqueror (Monthly)
    '4': 'price_1Ov1CnBWWWOdE1aoDykklTZh',  # The sky is the limit (Monthly)
    '2A': 'price_1Ov1C6BWWWOdE1aoMiVpxTBo',  # Adventurer (Annually)
    '3A': 'price_1Ov1BoBWWWOdE1ao8l9e677G',  # Conqueror (Annually)
    '4A': 'price_1Ov1CQBWWWOdE1aoa2weav8Iweav8I',  # The sky is the limit (Annually)
}

def app2stripe(plan_id):
	plan_ids = {
	2: 'price_1Ov19iBWWWOdE1ao04rdKBuw',  # Adventurer (Monthly)
    3: 'price_1Ov1B6BWWWOdE1aoH6dYugbz',  # Conqueror (Monthly)
    4: 'price_1Ov1CnBWWWOdE1aoDykklTZh',  # The sky is the limit (Monthly)
    2: 'price_1Ov1C6BWWWOdE1aoMiVpxTBo',  # Adventurer (Annually)
    3: 'price_1Ov1BoBWWWOdE1ao8l9e677G',  # Conqueror (Annually)
    4: 'price_1Ov1CQBWWWOdE1aoa2weav8Iweav8I',  # The sky is the limit (Annually)
	}
	sub_id=plan_ids.get(plan_id, 'none')
	return sub_id


#GET PARTNER ID OFF THE USER
def get_partner_id(user_id):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
	user = cursor.fetchone()
	partner_id = user['partner']
	# partner 1 = innovAitors
	if partner_id == 1:
		promo_code = "3W9uJiwq"
		print(f'[PARTNER] Session created - ACCOUNT : {user_id} - partner id : {partner_id} - promo code : {promo_code}')
	else:
		promo_code = None
	return promo_code

#CHECKOUT FROM PROMO BAR
#IT WILL LEAVE THE EMAIL EMTY IF THE USER IS NOT LOGGED IN
@app.route('/create-checkout-session-promo')
def create_checkout_session_promo():
	# USER IS LOGGED IN
	now = datetime.datetime.now()
	if loggedin():
		print(f"{now} - [PROMO CODE] user is logged in")
		cursor = mysql.connection.cursor()
		cursor.execute('SELECT email, username FROM accounts WHERE id = %s', (session['id'],))
		result = cursor.fetchone()
		mysql.connection.commit()
		cursor.close()
		email, username = result
		# CONQUERROR PLAN
		price_id = price_idz.get('3')
		try:
			checkout_session = stripe.checkout.Session.create(
				customer_email=email,
				line_items=[
					{
						"price": price_id,
						"quantity": 1
					}
				],
				mode="subscription",
				discounts=[{
					'coupon': 'nZsMwrYI',
					# 'coupon': 'sWkkT1fW',
				}],
				success_url='https://chatflux.io/checkout-success',
				cancel_url='https://chatflux.io/checkout-error'
			)
		except Exception as e:
			return str(e)
		return redirect(checkout_session.url, code=303)
	# USER IS NOT LOGGED IN
	else:
		print(f"{now} - [PROMO CODE] user is not logged in ")
		# email input in the stripe checkout page will be empty 
		# CONQUERROR PLAN
		price_id = price_idz.get('3')
		try:
			checkout_session = stripe.checkout.Session.create(
				line_items=[
					{
						"price": price_id,
						"quantity": 1
					}
				],
				mode="subscription",
				discounts=[{
					'coupon': 'nZsMwrYI',
					# 'coupon': 'sWkkT1fW',
				}],
				success_url='https://chatflux.io/checkout-success',
				cancel_url='https://chatflux.io/checkout-error'
			)
		except Exception as e:
			return str(e)
		return redirect(checkout_session.url, code=303)

# AUTOMATIC REGISTRATION AFTER CHECKOUT
def register_after_checkout(email):
	settings = get_settings()
	# Check if account exists using MySQL
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
	account = cursor.fetchone()
	
	user = email.split('@')
	username = user[0]+"-"+str(random.randint(10, 99))
	session["username"] = username
	characters = string.ascii_letters + string.digits + string.punctuation
	rand_passwordnothash = ''.join(random.choice(characters) for i in range(12))
	hash = rand_passwordnothash + app.secret_key
	hash = hashlib.sha1(hash.encode())
	rand_password = hash.hexdigest();
	role = 'Member'
	
	ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
	cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (%s, %s, %s, "activated", %s, %s)', (username, rand_password, email, role, ip,))
	mysql.connection.commit()

	# generating login token
	token = secrets.token_urlsafe(16)

	# Store the token in your database associated with the new account
	cursor.execute('UPDATE accounts SET auth_token = %s WHERE email = %s', (token, email,))
	mysql.connection.commit()

	# Send the token to the user email
	send_email_after_checkout(email,token)

	return 'You have registered! You can now login!'
	
# send email to use after checkout for login
def send_email_after_checkout(email,token):
	# Activate Link URL
	login_link = app.config['DOMAIN'] + "/verify?token=" + token
	# Create new message
	email_info = Message('Chatflux.io - Login Link', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [email])
	email_info.body = 'Hello,\nYou have successfully subscribed to Chatflux.io premium services. Please use the link below to login to your account. Thank you!\n\n' + login_link
	mail.send(email_info)
	return 'You have registered! You can now login!'

# verify token after checkout to login
@app.route('/verify')
def verify_token():

	# Generate random token that will prevent CSRF attacks
	csrf_token = uuid.uuid4()
	session['token'] = csrf_token
	
	settings = get_settings()
	login_token = request.args.get('token')
	if not login_token:
		print("No token provided")
		# 404 abort
		abort(404)

	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Verify the token and get user info
	cursor.execute('SELECT * FROM accounts WHERE auth_token = %s', (login_token,))
	account = cursor.fetchone()
	
	if account:
		ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
		# Check if account is activated
		if settings['account_activation']['value'] == 'true' and account['activation_code'] != 'activated' and account['activation_code'] != '':
			return 'Please activate your account to login!'
		# CSRF protection, form token should match the session token
		if settings['csrf_protection']['value'] == 'true' and str(csrf_token) != str(session['token']):
			return 'Invalid token!'
		# Two-factor
		if settings['twofactor_protection']['value'] == 'true' and account['ip'] != ip:
			session['tfa_id'] = account['id']
			session['tfa_email'] = account['email']
			return 'tfa: twofactor'
		# Create session data, we can access this data in other routes
		session['loggedin'] = True
		session['id'] = account['id']
		session['username'] = account['username']
		session['role'] = account['role']
		# Reset the attempts left
		cursor.execute('DELETE FROM login_attempts WHERE ip_address = %s', (ip,))
		mysql.connection.commit()
		# If the user checked the remember me checkbox...
		if 'rememberme' in request.form:
			rememberme_code = account['rememberme']
			if not rememberme_code:
				# Create hash to store as cookie
				rememberme_code = account['username'] + request.form['password'] + app.secret_key
				rememberme_code = hashlib.sha1(rememberme_code.encode())
				rememberme_code = rememberme_code.hexdigest()
			# the cookie expires in 90 days
			expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
			resp = make_response('Success', 200)
			resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
			# Update rememberme in accounts table to the cookie hash
			cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, account['id'],))
			mysql.connection.commit()
			# Return response
			return resp
		# Remove or invalidate the token in the database
		cursor.execute('UPDATE accounts SET auth_token = NULL WHERE id = %s', (account['id'],))
		mysql.connection.commit()
		
		return redirect(url_for('profile'))
	

	else:
		print("Invalid Token usage")
		abort(404)


#CHECKOUT STIPE	
@app.route('/create-checkout-session/<plan_id>')
def create_checkout_session(plan_id):
	cursor = mysql.connection.cursor()
	cursor.execute('SELECT email, username FROM accounts WHERE id = %s', (session['id'],))
	result = cursor.fetchone()
	mysql.connection.commit()
	cursor.close()
	email, username = result
	
	promo_code = get_partner_id(session['id'])
	price_id = price_idz.get(plan_id)
	if not price_id:
		return "Invalid plan ID", 400
	# promo code is not empty
	if promo_code:
		try:
			checkout_session = stripe.checkout.Session.create(
				customer_email=email,
				line_items=[
					{
						"price": price_id,
						"quantity": 1
					}
				],
				discounts=[{
					'coupon': promo_code,
				}],
				mode="subscription",
				success_url='https://chatflux.io/checkout-success',
				cancel_url='https://chatflux.io/checkout-error'
			)
		except Exception as e:
			return str(e)

		return redirect(checkout_session.url, code=303)
	# promo code is empty
	else:
		try:
			checkout_session = stripe.checkout.Session.create(
				customer_email=email,
				line_items=[
					{
						"price": price_id,
						"quantity": 1
					}
				],
				mode="subscription",
				allow_promotion_codes=True,
				success_url='https://chatflux.io/checkout-success',
				cancel_url='https://chatflux.io/checkout-error'
			)
		except Exception as e:
			return str(e)

		return redirect(checkout_session.url, code=303)



#WEBHOOK STRIPE
@app.route('/webhook', methods=['POST'])
def stripewebhook():
	endpoint_secret= 'whsec_IE1adPpZBLJnEtpA9F1ggEBjfWeXVEXB'
	event = None
	payload = request.data
	sig_header = request.headers['STRIPE_SIGNATURE']

	try:
		event = stripe.Webhook.construct_event(
			payload, sig_header, endpoint_secret
		)
	except ValueError as e:
		# Invalid payload
		raise e
	except stripe.error.SignatureVerificationError as e:
		# Invalid signature
		raise e
	# Handle the events
	#checkout completed
	if event['type'] == 'checkout.session.completed':
		session = event['data']['object']
		customer_email = session['customer_details']['email']
		subscription_id = session['subscription']
		# Retrieve subscription details
		subscription = stripe.Subscription.retrieve(subscription_id)
		# Get the price ID and product details
		price_id = subscription['items']['data'][0]['price']['id']
		product_id = subscription['items']['data'][0]['price']['product']
		product = stripe.Product.retrieve(product_id)
		product_name = product['name']
		print(f'webhook subscribed -> Customer : {customer_email} Upgraded to : {product_name}')
		update_account_plan(customer_email,price_id)
	#subscribtion canceled
	elif event['type'] == 'customer.subscription.deleted':
		subscription = event['data']['object']
		customer_id = subscription['customer']
		# Retrieve the customer's email address
		customer = stripe.Customer.retrieve(customer_id)
		customer_email = customer['email']
		print(f'cancelation webhook received : {customer_email}')
		revoke_plan(customer_email)
	elif event['type'] == 'invoice.payment_failed':
		invoice = event['data']['object']
		customer_id = invoice['customer']
		customer = stripe.Customer.retrieve(customer_id)
		customer_email = customer['email']
		print(f'payment failed for {customer_email}')
		handle_payment_failed(customer_email)
		#renewal
	elif event['type'] == 'invoice.payment_succeeded':
		invoice = event['data']['object']
		customer_id = invoice['customer']
		currentplan =  invoice['lines']['data'][0]['price']['id']
		customer = stripe.Customer.retrieve(customer_id)
		customer_email = customer['email']
		

		#check if a promo code was used
		bar_promo_code = '3kVtpoXy'
		if event['data']['object'].get('discount') is not None:
			promo_code = event['data']['object']['discount']['coupon']['id']
			if promo_code == bar_promo_code:
				#check if customer exists in db and update plan
				account = account_exists(customer_email)
				if account:
					print(f'promo code {promo_code} used for {customer_email}')
					update_account_plan(customer_email,currentplan)
					print(f'payment succeeded for {customer_email}, reseting monthly limits...')
					handle_payment_succeeded(customer_email)
				# ACCOUNT DOES NOT EXIST IN DB
				else:
					print(f'Registering user {customer_email}...')
					register_after_checkout(customer_email)
					print(f'promo code {promo_code} used for {customer_email}')
					print(f'PLAN : {stripe2app(currentplan)}')
					update_account_plan(customer_email,currentplan)
					print(f'payment succeeded for {customer_email}, reseting monthly limits...')
					handle_payment_succeeded(customer_email)
					# we should send an email to the user to inform him that he has been registered
					
				return jsonify(success=True)

		
		print(f'PLAN : {stripe2app(currentplan)}')
		update_account_plan(customer_email,currentplan)
		print(f'payment succeeded for {customer_email}, reseting monthly limits...')
		handle_payment_succeeded(customer_email)
	else:
		print('Unhandled event type {}'.format(event['type']))
	return jsonify(success=True)

def account_exists(email):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
	account = cursor.fetchone()
	mysql.connection.commit()
	cursor.close()
	print(f'account {email} => exists : {account}')
	return account

def handle_payment_failed(customer_email):
	revoke_plan(customer_email)
	email_info = Message('Chatflux.io - Payment Failed', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [customer_email])
	email_info.body = 'Hello,\nYour recent payment attempt has failed. We have temporarily revoked your plan until the payment issue is resolved. Please update your payment information as soon as possible to regain access to Chatflux.io premium services. Thank you!'
	mail.send(email_info)
	return 'Payment failed & Mail sent'

def handle_payment_succeeded(customer_email):
	# THE PROBLEM IS HERE, HE does not find te user in the database
	# FIX HERE
	# SOLUTION IF COUPON CODE IN CHECKOUT DATA IS THE PROMO ONE => HANDLE IT IN STIPE WEBHOOK
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT id FROM accounts WHERE email = %s", (customer_email,))
	user_id = cursor.fetchone()['id']
	#GETING COUNT FOR USER
	cursor.execute("UPDATE chatbot_interactions SET interaction_count=0 WHERE user_id=%s", (user_id,))
	mysql.connection.commit()
	cursor.close()
	print(f'Interactions reseted successfully for {user_id}')
	return 'Interactions Reseted'

def revoke_plan(customer_email):
	# Update the plan_id in the accounts table to None or a default value
	cursor = mysql.connection.cursor()
	cursor.execute("UPDATE accounts SET plan_id=1 WHERE email=%s", (customer_email,))
	print(f'revoked plan for user : {customer_email}')
	mysql.connection.commit()
	cursor.close()
	return 'Subscription canceled', 200

def currentplan(id):
	cursor = mysql.connection.cursor()
	cursor.execute('SELECT plan_id, username FROM accounts WHERE id = %s', (id,))
	result = cursor.fetchone()
	mysql.connection.commit()
	cursor.close()
	plan_id, username = result
	return plan_id

#CANCEL SUB DEF
# def cancel_plan(customer_email):
# 	customers = stripe.Customer.list(email=customer_email)
# 	if len(customers['data']) == 0:
# 		return 'Customer not found', 400
# 	customer = customers['data'][0]
# 	# List the subscriptions for the customer
# 	subscriptions = stripe.Subscription.list(customer=customer['id'], status='active')
# 	if len(subscriptions['data']) == 0:
# 		return 'No active subscription found', 400
# 	# Cancel the subscription in Stripe (assuming only one active subscription per customer)
# 	subscription = subscriptions['data'][0]
# 	stripe.Subscription.delete(subscription['id'])
# 	# Update the plan_id in the accounts table to None or a default value
# 	cursor = mysql.connection.cursor()
# 	cursor.execute("UPDATE accounts SET plan_id=1 WHERE email=%s", (customer_email,))
# 	print(f'canceled plan for user : {customer_email}')
# 	mysql.connection.commit()
# 	cursor.close()
# 	return 'Subscription canceled', 200

def account_update_subscription(customer_email, plan_id):
	try:
		cursor = mysql.connection.cursor()
		cursor.execute("UPDATE accounts SET plan_id=%s WHERE email=%s", (plan_id,customer_email))
		mysql.connection.commit()
		cursor.close()
	except Exception as e:
		print(f"Error updating account: {e}")

#UPDATE PLAN DEF
def appsumo_update_account_plan(customer_email, plan_id):
	try:
		cursor = mysql.connection.cursor()
		cursor.execute("UPDATE accounts SET plan_id=%s WHERE email=%s", (plan_id,customer_email))
		mysql.connection.commit()
		cursor.close()
	except Exception as e:
		print(f"Error updating account: {e}")

def update_account_plan(customer_email, subscription_id):
	plan_id=stripe2app(subscription_id)
	try:
		cursor = mysql.connection.cursor()
		cursor.execute("UPDATE accounts SET plan_id=%s WHERE email=%s", (plan_id,customer_email))
		mysql.connection.commit()
		cursor.close()
	except Exception as e:
		print(f"Error updating account: {e}")


# #CANCEL SUB ROUTE
# @app.route('/cancel-subscription')
# def cancel_subscription():
# 	cursor = mysql.connection.cursor()
# 	cursor.execute('SELECT email, username FROM accounts WHERE id = %s', (session['id'],))
# 	result = cursor.fetchone()
# 	mysql.connection.commit()
# 	cursor.close()
# 	customer_email, username = result
# 	cancel_message, cancel_status = cancel_plan(customer_email)
# 	return cancel_message, cancel_status

@app.route('/customer-portal')
def customer_portal():
	user_id = session['id']
	cursor = mysql.connection.cursor()
	cursor.execute('SELECT email, username FROM accounts WHERE id = %s', (user_id,))
	result = cursor.fetchone()
	mysql.connection.commit()
	cursor.close()
	customer_email, username = result
	customers = stripe.Customer.list(email=customer_email)
	if len(customers['data']) == 0:
		return render_template('customer404.html'),400 
	customer = customers['data'][0]
	
	return_url = "https://chatflux.io/profile"

	stripesession = stripe.billing_portal.Session.create(
		customer=customer['id'],
		return_url=return_url,
	)
	return redirect(stripesession.url, code=303)


@app.route('/checkout-error')
def checkout_error():
    return render_template('payementfailed.html')

@app.route('/checkout-success')
def checkout_success():
    return render_template('payementdone.html')

#PRICING
@app.route('/pricing/')
def pricing():
	account = ''
	if loggedin():
		# Retrieve all account info from the database
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
		account = cursor.fetchone()

	return render_template('pricing.html', account=account)

#API DOCUMENTATION
@app.route('/developers/')
def developers():
    return render_template('api.html')

#API KEY GENERATE
@app.route('/generate-api-key')#, methods=['POST']
def generate_api_key():

	if not loggedin():
		return redirect(url_for('login'))
	
	if not can_create_api(session['id']):
		return jsonify({"error": "Your plan does not support generating API keys. Please consider upgrading to unlock this feature."}), 403

	api_key = "API-CHATFLUX-A0"+str(uuid.uuid4())
	hashed_api_key = hashlib.sha256(api_key.encode('utf-8')).hexdigest()

	cursor = mysql.connection.cursor()
	cursor.execute("INSERT INTO api_keys (user_id, api_key) VALUES (%s, %s)", (session['id'], hashed_api_key))
	mysql.connection.commit()
	cursor.close()
	
	#GET USER INFO
	cursor = mysql.connection.cursor()
	cursor.execute('SELECT email, username FROM accounts WHERE id = %s', (session['id'],))
	result = cursor.fetchone()
	mysql.connection.commit()
	cursor.close()
	email, username = result
	#Create new email message
	email_info = Message('API KEY Request', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [email])
	# Email content
	email_info.body = 'Hello, '+ username+'\nWe are pleased to inform you that your request for an API key has been processed, please make sure to store it securely.\nThis is your unique API key: '+ api_key +'\nThe API Endpoint: https://chatflux.io/api/v1/chatbot\nIf you need more information regarding the API, please refer to our documentation : https://chatflux.io/developers'
	# Send mail
	mail.send(email_info)
	return jsonify({"success": "API Key has been sent to your email."}), 200


#VALIDATION OF API KEY
def validate_api_key(api_key):
	hashed_api_key = hashlib.sha256(api_key.encode('utf-8')).hexdigest()
	cursor = mysql.connection.cursor()
	cursor.execute("SELECT * FROM api_keys WHERE api_key=%s", (hashed_api_key,))
	result = cursor.fetchone()
	# If API key is valid, increment the api_usage column value
	if result is not None:
		cursor.execute("UPDATE api_keys SET api_usage = api_usage + 1 WHERE api_key = %s", (hashed_api_key,))
		mysql.connection.commit()
	cursor.close()
	return result is not None

from functools import wraps

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header is None or not auth_header.startswith('Bearer '):
            return jsonify({"message": "API key is missing or invalid"}), 401
        api_key = auth_header[7:]  # Remove the 'Bearer ' prefix
        if not validate_api_key(api_key):
            return jsonify({"message": "API key is missing or invalid"}), 401
        return f(*args, **kwargs)
    return decorated_function


#CHAT PROXY
@app.route('/chat', methods=['POST'])
@cross_origin(supports_credentials=True, origins=['https://gptify.io','https://chatflux.io'])
def chat_proxy():
	api_url = 'https://chatflux.io/api/v1/chatbot'
	api_key = 'API-GPTIFY-A0e1fa862b-5ab1-4277-954a-7a0ae6fb9d58'# store variable in env in prod

	headers = {
		'Content-Type': 'application/json',
		'Authorization': f'Bearer {api_key}',
	}

	data = request.get_json()
	chat_id = data.get('chatid') 
	
	# Check if the chatbot has email collection enabled
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT collect_emails FROM user_docs WHERE chat_id = %s', (chat_id,))
	collect_emails = cursor.fetchone()['collect_emails']
	
	# Only show email form if email collection is enabled and the user has not provided an email yet
	lead_collected = session.get('leaded')
	data['showEmailForm'] = collect_emails and not lead_collected

	# Check if a history ID exists
	if 'history_id' not in session:
		# If it doesn't, create a new one
		session['history_id'] = str(uuid.uuid4())
		#Remove later
		print(f"[+] New History ID Created =>\n{session['history_id']}")
	data['history_id'] = session['history_id']
	print("=> Using history id : "+session['history_id'])
	response = requests.post(api_url, headers=headers, json=data)
	# print(data)

	return jsonify(response.json()), response.status_code
	
@app.route('/toggle_collect_emails/<chat_id>', methods=['POST'])
def toggle_collect_emails(chat_id):
	if not loggedin():
		return redirect(url_for('login'))

	if not can_collect_leads(session['id']):
		return jsonify({'status': 'error'}), 400
	# Check if the chatbot belongs to the logged in user
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	collect_emails = bool(int(request.form.get('collect_emails')))

	cursor.execute(
		"UPDATE user_docs SET collect_emails = %s WHERE id = %s", 
		(collect_emails, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

#MANAGE METADATA FILES 
@app.route('/delete_file/<chat_id>', methods=['POST'])
def delete_file(chat_id):
	if not loggedin():
		return redirect(url_for('login'))

	if not can_manage_metadata(session['id']):
		return jsonify({'status': 'error'}), 400
	
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403
	
	file_name = request.form.get('file_name')
	
	# index = pinecone.Index("index1")
	index = pc.Index("index1")
	namespace = chat_id
	# index.delete(
	# 	namespace=namespace,
	# 	filter={
	# 	"filename": file_name
	# 	}
	# )
	index.delete(
		namespace=namespace,
		filter={
		"filename": file_name
		}
	)


	# Parse the JSON
	metadata = json.loads(chatbot['metadata'])

	# Filter out the file to be deleted
	updated_files = [f for f in metadata['files'] if f['file_name'] != file_name]

	# Update the 'files' key in the metadata
	metadata['files'] = updated_files

	# Convert the updated metadata back to JSON
	updated_metadata = json.dumps(metadata)

	# Update the metadata in the database
	cursor.execute('UPDATE user_docs SET metadata = %s WHERE id = %s', (updated_metadata, chatbot['id']))

	# Commit the changes and close the connection
	mysql.connection.commit()
	cursor.close()

	return "File deleted successfully.", 200


#BUBBLE POSITION
@app.route('/toggle_chat_bubble_placement/<chat_id>', methods=['POST'])
def toggle_chat_bubble_placement(chat_id):
	if not loggedin():
		return redirect(url_for('login'))

	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	
	# Check if the chatbot belongs to the logged in user
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	chat_bubble_placement = bool(int(request.form.get('chat_bubble_placement')))

	cursor.execute(
		"UPDATE user_docs SET chat_bubble_placement = %s WHERE id = %s", 
		(chat_bubble_placement, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))


@app.route('/upload_profile_pic/<chat_id>', methods=['POST'])
def upload_file(chat_id):

	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	# check if the post request has the file part
	if 'file' not in request.files:
		return jsonify(status="error", error="No file part in the request.")
	
	file = request.files['file']

	# if user does not select file, file variable can be empty
	if file.filename == '':
		return jsonify(status="error", error="No selected file.")
	
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		profilename = chat_id +"-"+ filename
		file_path = os.path.join(app.config['UPLOAD_FOLDER'], profilename)
		file.save(file_path)
		
		# update the database
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		sql = "UPDATE user_docs SET profile_pic = %s WHERE chat_id = %s"
		val = (file_path, chat_id)
		cursor.execute(sql, val)
		mysql.connection.commit()

		
		base_url = request.url_root
		image_url = base_url + file_path

		return jsonify(status="success", image_url = image_url)

	return jsonify(status="error", error="File upload error.")


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

#profile_pic
@app.route('/profile_pic_enable/<chat_id>', methods=['POST'])
def toggle_profilepic(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	
	# Check if the chatbot belongs to the logged in user
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	profile_pic_enabled = bool(int(request.form.get('profile_pic_enabled')))

	cursor.execute(
		"UPDATE user_docs SET profile_pic_enabled = %s WHERE id = %s", 
		(profile_pic_enabled, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#SUGGESTED MESSAGES 
@app.route('/update_suggested_messages', methods=['POST'])
def update_suggested_messages():
	
	data = request.get_json()
	chat_id = data.get('chat_id')
	suggested_messages = data.get('suggested_messages')
	
	if not can_suggest_messages(session['id']):
		return jsonify({'status': 'error'}), 400
	
	# Check if the chatbot belongs to the logged in user
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	try:
		cur = mysql.connection.cursor()
		cur.execute('UPDATE user_docs SET suggested_messages = %s WHERE chat_id = %s', (suggested_messages, chat_id,))
		mysql.connection.commit()
		return jsonify(status="success")
	
	except Exception as e:
		print(e)
		return jsonify(status="error"), 500

#HEADER
@app.route('/toggle_header/<chat_id>', methods=['POST'])
def toggle_header(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	# Check if the chatbot belongs to the logged in user
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	header_enabled = bool(int(request.form.get('header_enabled')))

	cursor.execute(
		"UPDATE user_docs SET header_enabled = %s WHERE id = %s", 
		(header_enabled, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#HEADER NAME
@app.route('/update_header_name/<chat_id>', methods=['POST'])
def update_header_name(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400

	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	header_name = request.form.get('header_name')

	cursor.execute(
		"UPDATE user_docs SET header_name = %s WHERE id = %s", 
		(header_name, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#TEXT COLOR
@app.route('/update_text_color/<chat_id>', methods=['POST'])
def update_text_color(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	text_color = request.json['color']

	cursor.execute(
		"UPDATE user_docs SET text_color = %s WHERE id = %s", 
		(text_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#HEADER COLOR
@app.route('/update_header_color/<chat_id>', methods=['POST'])
def update_header_color(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	header_color = request.json['color']

	cursor.execute(
		"UPDATE user_docs SET header_color = %s WHERE id = %s", 
		(header_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#USER MESSAGE COLOR
@app.route('/update_user_message_color/<chat_id>', methods=['POST'])
def update_user_message_color(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	user_msg_color = request.json['color']

	cursor.execute(
		"UPDATE user_docs SET user_msg_color = %s WHERE id = %s", 
		(user_msg_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#BOT MESSAGE COLOR
@app.route('/update_bot_message_color/<chat_id>', methods=['POST'])
def update_bot_message_color(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	bot_msg_color = request.json['color']

	cursor.execute(
		"UPDATE user_docs SET bot_msg_color = %s WHERE id = %s", 
		(bot_msg_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#BG COLOR
@app.route('/update_background_color/<chat_id>', methods=['POST'])
def update_background_color(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	background_color = request.json['color']

	cursor.execute(
		"UPDATE user_docs SET background_color = %s WHERE id = %s", 
		(background_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#THEME COLOR
@app.route('/update_custom_color/<chat_id>', methods=['POST'])
def update_custom_color(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400

	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403
	
	custom_color = request.json['color']

	cursor.execute(
		"UPDATE user_docs SET custom_color = %s WHERE id = %s", 
		(custom_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#RESET COLORS
@app.route('/reset_colors/<chat_id>', methods=['POST'])
def reset_colors(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	# Set default color as NULL for other color columns and "" for custom_color column
	default_color = None
	default_custom_color = ""

	cursor.execute(
		"""
		UPDATE user_docs SET 
		custom_color = %s,
		header_color = %s,
		text_color = %s,
		user_msg_color = %s,
		bot_msg_color = %s,
		background_color = %s 
		WHERE id = %s
		""", 
		(default_custom_color, default_color, default_color, default_color, default_color, default_color, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))



#LOADING STYLE
@app.route('/update_loading_style/<chat_id>', methods=['POST'])
def update_loading_style(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_customize_color(session['id']):
		return jsonify({'status': 'error'}), 400
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	loading_style = request.json['loadingStyle']

	cursor.execute(
		"UPDATE user_docs SET loading_style = %s WHERE id = %s", 
		(loading_style, chatbot['id'])
	)
	mysql.connection.commit()
	
	return redirect(url_for('mychatbots'))

#TOGGLE HUMAN ASSISTANCE
@app.route('/toggle_human_assistance/<chat_id>', methods=['POST'])
def toggle_human_assistance(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	if not can_add_human_help(session['id']):
		return jsonify({'status': 'error'}), 400
	# Check if the chatbot belongs to the logged in user
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
		(chat_id, session['id'])
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		return "Unauthorized", 403

	human_assistance = bool(int(request.form.get('human_assistance')))

	cursor.execute(
		"UPDATE user_docs SET human_assistance = %s WHERE id = %s", 
		(human_assistance, chatbot['id'])
	)
	mysql.connection.commit()

	return redirect(url_for('mychatbots'))

#TOGGLE GPT MODEL
@app.route('/toggle_gpt_model/<chat_id>', methods=['POST'])
def toggle_gpt_model(chat_id):
    if not loggedin():
        return redirect(url_for('login'))
    
    # Check if the chatbot belongs to the logged in user
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", 
        (chat_id, session['id'])
    )
    chatbot = cursor.fetchone()

    if chatbot is None:
        return "Unauthorized", 403

    gpt4 = bool(int(request.form.get('gpt4')))

    cursor.execute(
        "UPDATE user_docs SET gpt4 = %s WHERE id = %s", 
        (gpt4, chatbot['id'])
    )
    mysql.connection.commit()

    return redirect(url_for('mychatbots'))


@app.route('/api/v1/collect_email', methods=['POST'])
def collect_email():

	email = request.json.get('email')
	chatbot_id = request.json.get('chatbot_id')
	
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT user_id FROM user_docs WHERE chat_id = %s", (chatbot_id,))
	user_id = cursor.fetchone()['user_id']

	print(email,chatbot_id, user_id)

	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("INSERT INTO collected_emails (email, user_id, chatbot_id) VALUES ( %s, %s, %s)", (email, user_id, chatbot_id))	
	mysql.connection.commit()

	session['leaded'] = True  

	return jsonify({'status': 'success'})


@app.route('/export_emails/<chatbot_id>', methods=['GET'])
def export_emails(chatbot_id):
	if not loggedin():
		return redirect(url_for('login'))
    
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

	# Check if the chatbot belongs to the logged in user
	cursor.execute('SELECT user_id FROM user_docs WHERE chat_id = %s', (chatbot_id,))
	result = cursor.fetchone()
	
	if not result or result['user_id'] != session['id']:
		return "You are not authorized to download this data", 403

	# If it does belong to the user, fetch the emails
	cursor.execute('SELECT email FROM collected_emails WHERE chatbot_id = %s', (chatbot_id,))
	result = cursor.fetchall()

	def generate():
		data = StringIO()
		w = csv.writer(data)

		# write header
		w.writerow(('LEADS',))
		yield data.getvalue()
		data.seek(0)
		data.truncate(0)

		# write each item
		for item in result:
			w.writerow((item['email'],))
			yield data.getvalue()
			data.seek(0)
			data.truncate(0)

	return Response(generate(), mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=emails_" + chatbot_id + ".csv"})

# Allowing domains
def check_origin(origin):
	parsed_origin = urlparse(origin)
	domain = parsed_origin.netloc

	cursor = mysql.connection.cursor()
	cursor.execute("SELECT domain FROM allowed_domains WHERE domain = %s", (domain,))
	result = cursor.fetchone()

	if result is not None:
		return origin
	return None

def get_allowed_origins():
	cursor = mysql.connection.cursor()
	cursor.execute("SELECT domain FROM allowed_domains")
	results = cursor.fetchall()
	allowed_origins = [row[0] for row in results]
	return allowed_origins

@app.after_request
def after_request(response):
	origin = request.headers.get('Origin')
	allowed_origin = check_origin(origin)

	if allowed_origin is not None:
		response.headers.add('Access-Control-Allow-Origin', allowed_origin)
		response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
		response.headers.add('Access-Control-Allow-Methods', 'GET,POST')

	return response



#defs
def clear_submit():
	session["submit"]= False

docsearch = None
doc = None

# ALLOW DOMAIN
@app.route('/api/v1/add_domain', methods=['POST'])
def add_domain():
	domain = request.form.get('domain')
	if domain:
		cursor = mysql.connection.cursor()
		cursor.execute("SELECT domain FROM allowed_domains WHERE domain = %s", (domain,))
		existing_domain = cursor.fetchone()
		if not existing_domain:
			cursor.execute("INSERT INTO allowed_domains (domain,user_id) VALUES (%s, %s)", (domain,session['id']))
			mysql.connection.commit()
			return jsonify({"message": "Domain added successfully"}), 200
		else:
			return jsonify({"message": "Domain already exists"}), 400
	return jsonify({"message": "Invalid domain"}), 400

@app.route('/contact/<chat_id>')
def contact(chat_id):
    # Check if the chatbot belongs to the logged in user and if human assistance is enabled
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "SELECT * FROM user_docs WHERE chat_id = %s AND human_assistance = 1", 
        (chat_id,)
    )
    chatbot = cursor.fetchone()

    if chatbot is None:
        # Redirect to 404 if chatbot with provided chat_id does not exist or human assistance is not enabled
        abort(404)

    return render_template('askhuman.html', chat_id=chat_id)

@app.route('/contact_us', methods=['POST'])
def contact_us():
	#ADD IF ENABLED
	full_name = request.form.get('full_name')
	email = request.form.get('email')
	message = request.form.get('message')
	chat_id = request.form.get('chatbotid')
	
	# Check if the chatbot belongs to the logged in user and if human assistance is enabled
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute(
		"SELECT * FROM user_docs WHERE chat_id = %s AND human_assistance = 1", 
		(chat_id,)
	)
	chatbot = cursor.fetchone()

	if chatbot is None:
		# Redirect to 404 if chatbot with provided chat_id does not exist or human assistance is not enabled
		abort(404)

	#GET OWNER MAIL
	
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT user_id FROM user_docs WHERE chat_id = %s', (chat_id,))
	user_id = cursor.fetchone()['user_id']

	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT document_name FROM user_docs WHERE chat_id = %s', (chat_id,))
	document_name = cursor.fetchone()['document_name']

	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve account info from database that's associated with the captured user id
	cursor.execute('SELECT email FROM accounts WHERE id = %s', (user_id,))
	owner = cursor.fetchone()['email']
	print(f"owner email : {owner}")

	email_info = Message('Chatflux.io - New Message from Contact Form',
						sender=app.config['MAIL_DEFAULT_SENDER'],
						recipients=[owner])
	
	email_info.body = f"A user named '{full_name}' has sent a message from the contact form.\nChatbot : {document_name} \nEmail: {email}\nMessage:\n{message}"
	
	mail.send(email_info)
	
	return render_template('mailsent.html')


@app.route('/chatbot/make_chatbot_public/<chat_id>')
def make_chatbot_public(chat_id):
	# Verify if chatbot exists
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	mychatbot = cursor.fetchone()
	if loggedin() and session['id'] == mychatbot['user_id']:
		cursor = mysql.connection.cursor()
		cursor.execute("UPDATE user_docs SET public=1 WHERE chat_id=%s", (chat_id,))
		mysql.connection.commit()
		return jsonify({'status': 'success'})
	else:
		return jsonify({'status': 'error'})
	

@app.route('/chatbot/make_chatbot_private/<chat_id>')
def make_chatbot_private(chat_id):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	mychatbot = cursor.fetchone()
	if loggedin() and session['id'] == mychatbot['user_id']:
		cursor = mysql.connection.cursor()
		cursor.execute("UPDATE user_docs SET public=0 WHERE chat_id=%s", (chat_id,))
		mysql.connection.commit()
		return jsonify({'status': 'success'})
	else:
		return jsonify({'status': 'error'})

#UNIQUE CHATBOT
@app.route('/chatbot/<chat_id>/')
def chatbot(chat_id):
	if not chat_id:
		return redirect(url_for('mychatbots'))
	
	# Verify if chatbot exists
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	mychatbot = cursor.fetchone()
	
	# If chatbot exists
	if mychatbot:
		
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
		mychatbot = cursor.fetchone()
		doc = mychatbot['document_name']
		def is_valid_url(url):
			try:
				result = urlparse(url)
				return all([result.scheme, result.netloc])
			except ValueError:
				return False
			
		if is_valid_url(doc):
			chatname = mychatbot['document_name']

		elif mychatbot['document_name'].endswith(('.txt', '.docx', '.pdf')):
			chatname = mychatbot['document_name'][:-4]
		else:
			chatname = mychatbot['document_name']

		if mychatbot['public'] == 1:
			
			# Chatbot is public, skip login check
			return render_template('chatbot.html', chatname=chatname , mychatbot=mychatbot)
		else:
			# Chatbot is private, check if user is logged in and the user_id matches
			if loggedin() and session['id'] == mychatbot['user_id']:
				
				return render_template('chatbot.html', chatname=chatname, mychatbot=mychatbot)
			else:
				return redirect(url_for('login'))
	else:
		return redirect(url_for('mychatbots'))

#MYCHATBOTS
# @app.route('/mychatbots/')
# def mychatbots():
# 	if not loggedin():
# 		return redirect(url_for('login'))
# 	# Get the total number chatbots
# 	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 	cursor.execute('SELECT * FROM user_docs WHERE user_id = %s ', ( session['id'],))
# 	mychatbots = cursor.fetchall()
	
# 	 # Get count of collected emails grouped by chatbot_id
# 	cursor.execute('SELECT chatbot_id, COUNT(*) as email_count FROM collected_emails GROUP BY chatbot_id')
# 	email_counts = cursor.fetchall()

# 	# Get the interaction count for each chatbot
# 	for chatbot in mychatbots:
# 		cursor.execute('SELECT interaction_count FROM chatbot_interactions WHERE chat_id = %s ', (chatbot['chat_id'],))
# 		interaction_count = cursor.fetchone()
# 		chatbot['interaction_count'] = interaction_count['interaction_count'] if interaction_count else 0
		
# 	# Add email_counts to the mychatbots list
# 	for chatbot in mychatbots:
# 		for email_count in email_counts:
# 			if chatbot['chat_id'] == email_count['chatbot_id']:
# 				chatbot['email_count'] = email_count['email_count']
		
# 	return render_template('mybots2.html', chatbots=mychatbots, username=session['username'], role=session['role'])

#TESTING
@app.route('/mychatbots/')
def mychatbots():
	if not loggedin():
		return redirect(url_for('login'))
	# Get the total number chatbots
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE user_id = %s ', ( session['id'],))
	mychatbots = cursor.fetchall()
	
	for chatbot in mychatbots:
		if chatbot['metadata']: # Ensure that metadata is not None
			chatbot['metadata'] = json.loads(chatbot['metadata'])
		else:
			chatbot['metadata'] = {"files": []}

	# Get count of collected emails grouped by chatbot_id
	cursor.execute('SELECT chatbot_id, COUNT(*) as email_count FROM collected_emails GROUP BY chatbot_id')
	email_counts = cursor.fetchall()

	# Get the interaction count for each chatbot
	for chatbot in mychatbots:
		cursor.execute('SELECT interaction_count FROM chatbot_interactions WHERE chat_id = %s ', (chatbot['chat_id'],))
		interaction_count = cursor.fetchone()
		chatbot['interaction_count'] = interaction_count['interaction_count'] if interaction_count else 0
		
	# Add email_counts to the mychatbots list
	for chatbot in mychatbots:
		for email_count in email_counts:
			if chatbot['chat_id'] == email_count['chatbot_id']:
				chatbot['email_count'] = email_count['email_count']
		
	return render_template('mybots.html', chatbots=mychatbots, username=session['username'], role=session['role'])
	

def get_custom_prompt_base(chat_id):
	try:
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
		mychatbot = cursor.fetchone()
		cursor.close()
	except Exception as e:
		print(f"Error getting custom prompt base: {e}")
		return None
	
	custom_prompt_base = mychatbot['custom_prompt_base']
	return custom_prompt_base if mychatbot else None

def get_answerv(chat_id):
	try:
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
		mychatbot = cursor.fetchone()
		cursor.close()
	except Exception as e:
		print(f"Error getting custom prompt base: {e}")
		return None
	
	pickle_file_name = mychatbot['pickle_file_name']
	if pickle_file_name == "":
		version = 2
	else:
		version = 1
	return version
	

# History of chatbot interactions
def get_chatbot_history(cursor, chat_id, user_id, history_id):
    """
    Retrieves and ensures the chatbot history for the given history_id from the database.
    """
    cursor.execute("SELECT history FROM chatbot_interactions WHERE chat_id = %s AND user_id = %s", (chat_id, user_id))
    result = cursor.fetchone()
    chatbot_history_dict = {}

    # Check if history exists in the database
    if result and result['history']:
        chatbot_history_dict = json.loads(result['history'])

    # Check if the specific history_id exists in the chatbot history dictionary
    if history_id not in chatbot_history_dict:
        # If not, initialize an empty history for this history_id
        chatbot_history_dict[history_id] = []
        print(f"[+] Created new history for history_id {history_id}")

    return chatbot_history_dict

# Update chatbot history in the database		
def update_chatbot_history(cursor, chat_id, user_id, chatbot_history_dict):
    """
    Updates the chatbot history in the database.
    """
    updated_chatbot_history_json = json.dumps(chatbot_history_dict)
    cursor.execute("UPDATE chatbot_interactions SET history = %s WHERE chat_id = %s AND user_id = %s", (updated_chatbot_history_json, chat_id, user_id))

# Process interaction
def process_interaction(cursor, chat_id, user_id, history_id, query, answer):
	"""
	Processes a new interaction and updates the chatbot history.
	"""
	# Get the chatbot history
	chatbot_history_dict = get_chatbot_history(cursor, chat_id, user_id, history_id)

	# Append the new interaction to the chatbot history
	chatbot_history_dict[history_id].append("Human: " + query)
	chatbot_history_dict[history_id].append("AI: " + answer)

	# Limit the history to the last 15 interactions
	chatbot_history_dict[history_id] = chatbot_history_dict[history_id][-8:]

	# Updating the chatbot history
	update_chatbot_history(cursor, chat_id, user_id, chatbot_history_dict)

#API
@app.route('/api/v1/chatbot', methods=['POST'])
@api_key_required
def chatbot_api():
	try:##REMOVE DEBUGGIN PURPUSE
		if request.method == 'POST':

			user_input = request.json['message']
			foldid = request.json['chatid']
			showemailform = request.json.get('showEmailForm', None)
			history_id = request.json.get('history_id', None)
			
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (foldid,))
			mychatbot = cursor.fetchone()
			if not mychatbot:
				response = {"chatid":foldid,"input": user_input, "answer": "Chat ID Not Found"}
				return jsonify(response)
			if 'generated' not in session:
				session['generated'] = []	   
			if 'past' not in session:
				session['past'] = []	   
			if not user_input:
				answer = "Please enter a question"
			else:
				#sources = search_docs(foldid)#loading the doc
				print("Checking Limits...")

			#GETTING USER ID FROM CHATBOT
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute("SELECT user_id FROM user_docs WHERE chat_id = %s", (foldid,))
			user_id = cursor.fetchone()['user_id']

			# #CHECKING IF USER CAN USE API
			# if not can_create_api(user_id):
			# 	response = {"chatid":foldid,"input": user_input, "answer": "Your plan does not support API usage. Please consider upgrading to unlock this feature."}
			# 	return jsonify(response)
			
			#GETING COUNT FOR USER
			cursor.execute("SELECT SUM(interaction_count) as count FROM chatbot_interactions WHERE user_id = %s", (user_id,))
			interaction_count_result = cursor.fetchone()
			interaction_count = interaction_count_result['count'] if interaction_count_result['count'] else 0
			print(f"Current Interaction Count for User : {user_id}  is -> {interaction_count}")

			#GETTING LIMIT
			cursor.execute("SELECT accounts.plan_id, plans.chatbot_interaction_limit FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
			plan_info = cursor.fetchone()
			interaction_limit = plan_info['chatbot_interaction_limit']
			print(f'Current User Limit is : {interaction_limit}')

			#GPT LIMITS
			gpt4_interaction_limit = 1000 
			cursor.execute("SELECT SUM(gpt4_interactions) as count FROM chatbot_interactions WHERE user_id = %s", (user_id,))
			gpt4_interaction_count_result = cursor.fetchone()
			gpt4_interaction_count = gpt4_interaction_count_result['count'] if gpt4_interaction_count_result['count'] else 0
			print(f"Current GPT-4 Interaction Count for User : {user_id}  is -> {gpt4_interaction_count}")

			# Check if the chatbot is set to use GPT-4
			cursor.execute("SELECT gpt4 FROM user_docs WHERE chat_id = %s AND user_id = %s", (foldid, user_id))
			chatbotz = cursor.fetchone()
			use_gpt4 = bool(chatbotz['gpt4'])
			
			if not interaction_limit != 0:
				# Decide which model to use based on preference and interaction count
				use_gpt4 = use_gpt4 and gpt4_interaction_count < gpt4_interaction_limit
				
				# Switch to GPT-3.5 Turbo if GPT-4 limit is exceeded
				if gpt4_interaction_count >= gpt4_interaction_limit and user_id != 1:
				#if gpt4_interaction_count >= 1000: 

					print(f'switched chatbot to model {use_gpt4}')
					use_gpt4 = False
					cursor.execute(
						"UPDATE user_docs SET gpt4 = %s WHERE chat_id = %s", 
						(0, foldid)
					)
					mysql.connection.commit()

			#CHECKING LIMIT
			if interaction_limit != 0 and interaction_count >= interaction_limit:
				response = {"chatid":foldid,"input": user_input, "answer": "You have reached the limit for chatbot interactions. Upgrade your plan to increase your monthly interactions."}
				print(f"Limit exceeded for user {user_id}")
				return jsonify(response)

			#GETTING THE HISTORY OF THIS CHATBOT
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			all_chatbot_history = get_chatbot_history(cursor, foldid, user_id, history_id)
			chatbot_history = all_chatbot_history[history_id]
			mysql.connection.commit()
			cursor.close()
			


			#ALL OK 
			try:
				custom_prompt_base = get_custom_prompt_base(foldid)
				version = get_answerv(foldid)
				
				if version == 2:
					print("Using Pinecone")
					answer,cost = get_answer4(chatbot_history, foldid, user_input, custom_prompt_base, use_gpt4)

				else:
					print("Using Chromadb")
					answer,cost = get_answer(foldid, user_input, custom_prompt_base)
					
				#answer,cost = get_answer(sources, user_input)
				print("jbt ljawab")
				#EMAIL COLLECTION + RESPONSE
				response = {
					"chatid": foldid,
					"input": user_input,
					"answer": answer,
				}

				# add 'showEmailForm' to response only if it was provided in the request
				if showemailform is not None:
					response['showEmailForm'] = showemailform

				cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
				# print("inserting new cost:",cost)
				cursor.execute("UPDATE user_docs SET cost = cost + %s WHERE chat_id = %s", (cost, foldid))
				mysql.connection.commit()
				# insert count
				cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
				
				# Check if there is already an interaction line for the chatbot
				cursor.execute("SELECT id, last_interaction FROM chatbot_interactions WHERE user_id = %s AND chat_id = %s", (user_id, foldid))
				interaction_exists = cursor.fetchone()

				# Set a minimum time between requests, for example, 2 seconds
				minimum_time_between_requests = timedelta(seconds=2)

				# If there is no line, create a new one
				if not interaction_exists:
					cursor.execute("INSERT INTO chatbot_interactions (user_id, chat_id, interaction_count, gpt4_interactions, last_interaction) VALUES (%s, %s, 0, 0, NOW())", (user_id, foldid))
					mysql.connection.commit()
				else:
					last_interaction = interaction_exists['last_interaction']

					# Check if enough time has passed since the last request
					if (datetime.datetime.now() - last_interaction) < minimum_time_between_requests:
						response = {"chatid":foldid, "input": user_input, "answer": "Too many requests. Please wait a moment before sending another request."}
						return jsonify(response)


				# Increment the interaction count in the chatbot_interactions table
				if use_gpt4:  # If using GPT-4
					if not interaction_limit != 0:  # If user has unlimited plan
						cursor.execute("UPDATE chatbot_interactions SET gpt4_interactions = gpt4_interactions + 1, interaction_count = interaction_count + 1, last_interaction = NOW() WHERE user_id = %s AND chat_id = %s", (user_id, foldid))
					else:  # If user does not have unlimited plan
						cursor.execute("UPDATE chatbot_interactions SET gpt4_interactions = gpt4_interactions + 1, interaction_count = interaction_count + 25, last_interaction = NOW() WHERE user_id = %s AND chat_id = %s", (user_id, foldid))
				else:  # If using GPT-3.5 Turbo
					cursor.execute("UPDATE chatbot_interactions SET interaction_count = interaction_count + 1, last_interaction = NOW() WHERE user_id = %s AND chat_id = %s", (user_id, foldid))
				
				mysql.connection.commit()

				# Process the interaction in the chatbot history
				cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
				process_interaction(cursor, foldid, user_id, history_id, user_input, answer)
				mysql.connection.commit()
				cursor.close()


				#print(f"Updated interaction count for user {user_id} with chatbot {foldid}")
				print("---"*10)
				return jsonify(response)
				#source : answer['source_documents']
			except OpenAIError as e:
				answer = e._message
		return jsonify({"message": "An error occurred"}) 
	except  Exception as e:
		print(e)

#YOUTUBE UPLOAD
@app.route('/youtubeupdate/<chat_id>/')
def youtubeupdate(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('youtubeupdate.html', msg=msg, chat_id=chat_id)

# UPDATE YOUTUBE
@app.route('/updatevideo', methods=['POST'])
def updatevideo():
	msg =''
	if not loggedin():
		return redirect(url_for('login'))
	
	# Check if the user can import data from YouTube based on their plan
	if not can_import_youtube_data(session['id']):
		msg = "Importing data from YouTube is not allowed on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to unlock this feature."
		flash(msg)
		return redirect(url_for('youtubecreate'))
	
	# Check if the user can create a new chatbot
	# if not can_create_chatbot(session['id']):
	# 	msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
	# 	flash(msg)
	# 	return redirect(url_for('youtubecreate'))
	
	video_urls = []
	
	index = 0
	missing_count = 0
	max_allowed_missing = 100  # This can be adjusted based on your use case

	while missing_count < max_allowed_missing:
		video_key = f'youtube_video-{index}'
		video_url = request.form.get(video_key)

		if video_url:
			video_urls.append(video_url)
			missing_count = 0  # Reset missing count if a video is found
		else:
			missing_count += 1

		index += 1

	merged_list = []
	chat2update = request.form.get('chatid')
	start_time = time.time()
	
	error_messages = []
	for vid in video_urls:
		print(vid)
		try:
			id = extract.video_id(vid)
		except Exception as e:
			msg = f"We could not find the video ID in {vid} . Make sure the YouTube link is correct"
			print(e)
			error_messages.append(msg)
			flash(msg)
			return redirect(url_for('youtubecreate'))

		try:
			id = extract.video_id(vid)
			print(id)
			# Retrieve the available transcripts
			transcript_list = YouTubeTranscriptApi.list_transcripts(id)
			# Iterate over all available transcripts
			for transcript in transcript_list:
				lang = transcript.language_code
			print(f"Language detected is : {lang} in {id}")

		except Exception as e:
			
			if 'Subtitles are disabled for this video' in str(e):
				msg = f"We apologize for the inconvenience, but we regret to inform you that subtitles are disabled for this video : {vid}."
				error_messages.append(msg)
				continue
			else:
				msg = 'An error occurred. If the error persists, please contact support.'
				print(f'Error: {e}')
				error_messages.append(msg)
				continue
			
			#getting trascript of the video
		if error_messages:
			for msg in error_messages:
				flash(msg)
			return redirect(url_for('youtubecreate'))
		
		trans,meta,msg = youtubefy(id)

		title="Chatbot From Youtube Video"

		try:
			time.sleep(15)
			yt = YouTube(vid, use_oauth=True, allow_oauth_cache=True)
			title = yt.title
			
			print(title)
			
		except  Exception as e:
			print(e)
			

		try: 
			docs = text_to_docsv2(trans, title)
			# old  metadata update - not needed anymore
			# for d in docs:
			# 	d.metadata.update(meta)

				
		except Exception as e:
			msg = 'An error occurred while accessing videos. Please try again. If the error persists, please contact support.'
			flash(msg)
			print(f'Error: {e}')
			return redirect(url_for('youtubecreate'))
		vid = vid

		merged_list.extend(docs)
		
		
	
		
	try:			
		chat_id, cost = update_docs(merged_list , chat2update , title)
		persist_directory = ""
		
		
		sid = session['id'] 
		print("video indexed ok")
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		# Fetch the existing metadata
		cursor.execute("SELECT metadata FROM user_docs WHERE chat_id = %s", (chat_id,))
		row = cursor.fetchone()

		# Parse the existing metadata
		existing_metadata = json.loads(row['metadata']) if row and row['metadata'] else {"files": []}

		# Append new file to the metadata's "files" list
		existing_metadata["files"].append({"file_name": title, "created_at": current_datetime})

		# Convert the metadata back to a JSON string
		new_metadata_json = json.dumps(existing_metadata)

		
		cursor.execute("UPDATE user_docs SET cost = cost + %s, metadata = %s WHERE chat_id = %s", (cost, new_metadata_json, chat_id))

		#cursor.execute("UPDATE user_docs SET cost = cost + %s WHERE chat_id = %s", (cost,chat_id))
		mysql.connection.commit()
		print(f"chat id updated : {chat_id}")

		elapsed_time = time.time() - start_time
		if elapsed_time > 60:
			# Set a flag to send an email notification
			send_email_notification = True
			user_id = session['id']
		else:
			send_email_notification = False

			
		if send_email_notification:
			# Send the email notification
			send_chatbot_created_email(user_id, chat_id)
			return  redirect(url_for('chatbot', chat_id=chat_id))
		else:
			return  redirect(url_for('chatbot', chat_id=chat_id))

	except OpenAIError as e:
		return e._message
	except  Exception as e:
		print(e)


#YOUTUBE UPLOAD
@app.route('/youtubecreate/')
def youtubecreate():
	if not loggedin():
		return redirect(url_for('login'))
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('youtube2.html', msg=msg)

# UPLOAD YOUTUBE
@app.route('/addvideo2', methods=['POST'])
def addvideo2():
	msg =''
	if not loggedin():
		return redirect(url_for('login'))
	
	# Check if the user can import data from YouTube based on their plan
	if not can_import_youtube_data(session['id']):
		msg = "Importing data from YouTube is not allowed on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to unlock this feature."
		flash(msg)
		return redirect(url_for('youtubecreate'))
	
	# Check if the user can create a new chatbot
	if not can_create_chatbot(session['id']):
		msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
		flash(msg)
		return redirect(url_for('youtubecreate'))
	
	video_urls = []
	index = 0
	missing_count = 0
	max_allowed_missing = 100  # This can be adjusted based on your use case

	while missing_count < max_allowed_missing:
		video_key = f'youtube_video-{index}'
		video_url = request.form.get(video_key)

		if video_url:
			video_urls.append(video_url)
			missing_count = 0  # Reset missing count if a video is found
		else:
			missing_count += 1

		index += 1
		
	merged_list = []
	
	doc_id = uuid.uuid4()
	user_id = session['id']
	chat_id = f"{user_id}_{doc_id}"
	start_time = time.time()
	print("starting")
	error_messages = []
	for vid in video_urls:
		print(vid)
		try:
			id = extract.video_id(vid)
		except Exception as e:
			msg = f"We could not find the video ID in {vid} . Make sure the YouTube link is correct"
			print(e)
			error_messages.append(msg)
			flash(msg)
			return redirect(url_for('youtubecreate'))

		try:
			id = extract.video_id(vid)
			print(id)
			# Retrieve the available transcripts
			transcript_list = YouTubeTranscriptApi.list_transcripts(id)
			# Iterate over all available transcripts
			for transcript in transcript_list:
				lang = transcript.language_code
			print(f"Language detected is : {lang} in {id}")

		except Exception as e:
			
			if 'Subtitles are disabled for this video' in str(e):
				msg = f"We apologize for the inconvenience, but we regret to inform you that subtitles are disabled for this video : {vid}."				
				error_messages.append(msg)
				continue
				
			else:
				msg = 'An error occurred. If the error persists, please contact support.'
				print(f'Error: {e}')
				error_messages.append(msg)
				continue
			
			#getting trascript of the video
		if error_messages:
			for msg in error_messages:
				flash(msg)
			return redirect(url_for('youtubecreate'))
		
		trans,meta,msg = youtubefy(id)


		title=f"Chatbot From Youtube video"

		try:
			yt = YouTube(vid, use_oauth=True, allow_oauth_cache=True)
			title = yt.title
			
			print(title)
			
		except  Exception as e:
			print(e)
			
		title.encode('utf-8')


		try: 

			# docs = text_to_docs(trans)
			docs = text_to_docsv2(trans, title)

			# old metadata update - not used anymore
			# for d in docs:
			# 	d.metadata.update(meta)
		except Exception as e:
			msg = 'An error occurred while accessing videos. Please try again. If the error persists, please contact support.'
			flash(msg)
			print(f'Error: {e}')
			return redirect(url_for('youtubecreate'))
		vid = vid

		merged_list.extend(docs)
		
		
	

	try:			
		cost = embed_docs2(merged_list , chat_id, title)
		persist_directory = ""

		current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		# Prepare the metadata as a dictionary
		metadata = {
			"files": [
				{"file_name": title, "created_at": current_datetime}
			]
		}
		# Convert the metadata to a JSON string
		metadata_json = json.dumps(metadata)
		
		print("video indexed ok")
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		#cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name,cost) VALUES ( %s, %s, %s, %s, %s)", (session['id'], title, chat_id, persist_directory,cost))
		cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name, cost, metadata) VALUES ( %s, %s, %s, %s, %s, %s)", 
		  (session['id'], title, chat_id, persist_directory, cost, metadata_json))
		

		mysql.connection.commit()
		print(f"chat id inserted : {chat_id}")

		elapsed_time = time.time() - start_time
		if elapsed_time > 60:
			# Set a flag to send an email notification
			send_email_notification = True
			user_id = session['id']
		else:
			send_email_notification = False

			
		if send_email_notification:
			# Send the email notification
			send_chatbot_created_email(user_id, chat_id)
			return  redirect(url_for('chatbot', chat_id=chat_id))
		else:
			return  redirect(url_for('chatbot', chat_id=chat_id))

	except OpenAIError as e:
		return e._message
	except  Exception as e:
		print(e)

@app.route('/get-youtube-playlist', methods=['GET'])
def get_youtube_playlist():
	playlist_url = request.args.get('playlistUrl')
	video_urls = []
	# Create a Playlist object
	playlist = Playlist(playlist_url)
	for url in playlist.video_urls:
		video_urls.append(url)
	# The 'video_urls' attribute of a Playlist object contains all video URLs
	
	print(video_urls)

	return jsonify({'videoUrls': video_urls})



@app.route('/get_crawling_status')
def get_status():
    user_id = session['id']
    data = status_data.get(user_id, {
        'estimated_time': 0,
        'hyperlinks_remaining': 0,
        'hyperlinks_processed': 0
    })
    return jsonify(data)

#WEBSITE Update
@app.route('/urlupdate/<chat_id>/')
def urlupdate(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('updatewebsite.html', msg=msg, chat_id=chat_id)

#WEBSITE UPLOAD
@app.route('/urlcreate/')
def urlcreate():
	if not loggedin():
		return redirect(url_for('login'))
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	
	return render_template('websites2.html', msg=msg)


@app.route('/addsite2', methods=['POST'])
def addsite2():
	
	# Check if the user can create a new chatbot
	if not can_create_chatbot(session['id']):
		msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
		return jsonify({"error": msg, "hyperlinks": []})

	
	# Check if the user can import data from websites based on their plan
	if not can_import_website_data(session['id']):
		msg = "Importing data from Websites is not allowed on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to unlock this feature."
		return jsonify({"error": msg, "hyperlinks": []})
	
	site = request.form['site']
	print(site)

	timeout = 90
	max_links = 100
	start_time = time.time()
	hyperlinks = []

	with ThreadPoolExecutor(max_workers=1) as executor:
		future_hyperlinks = executor.submit(get_domain_hyperlinks2, site, depth=2, max_links=max_links)
		try:
			hyperlinks = future_hyperlinks.result(timeout=timeout)
		except Exception as e:
			pass

	return jsonify(hyperlinks)

#UPDATE WEBSITE EMBEDING
@app.route('/add_hyperlinks_update', methods=['POST'])
def add_hyperlinks_update():

	chat2update = request.get_json().get('chatid')

	if not loggedin():
		return redirect(url_for('login'))
	# Check if the user can create a new chatbot
	if not can_create_chatbot(session['id']):
		msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
		flash(msg)
		return redirect(url_for('urlcreate'))
	# Check if the user can import data from websites based on their plan
	if not can_import_website_data(session['id']):
		msg = "Importing data from Websites is not allowed on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to unlock this feature."
		flash(msg)
		return redirect(url_for('urlcreate'))
	
	hyperlinks = request.get_json().get('links', [])
	print(hyperlinks)

	if not hyperlinks:
		print("not")
		msg = "Please provide at least one hyperlink."
		flash(msg)
		return redirect(url_for('urlcreate'))

	try:
		start_time = time.time()
		combined_text, url = sitefy(hyperlinks, session['id'])
		elapsed_time = time.time() - start_time
		if elapsed_time > 60:
			# Set a flag to send an email notification
			send_email_notification = True
			user_id = session['id']
		else:
			send_email_notification = False
	except requests.exceptions.RequestException as e:
		print(f"Error with proxies : {e}")
		msg= "An error occured, please retry in a few seconds. If the error persist, please contact support@chatflux.io"
		flash(msg)
		return redirect(url_for('urlcreate'))

	text = text_to_docsv2(combined_text, url)
	# text = text_to_docs(combined_text)

	chat_id, cost = update_docs(text, chat2update, url)
	
	print("indexed ok")
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	# Fetch the existing metadata
	cursor.execute("SELECT metadata FROM user_docs WHERE chat_id = %s", (chat_id,))
	row = cursor.fetchone()

	# Parse the existing metadata
	existing_metadata = json.loads(row['metadata']) if row and row['metadata'] else {"files": []}

	# Append new file to the metadata's "files" list
	existing_metadata["files"].append({"file_name": url, "created_at": current_datetime})

	# Convert the metadata back to a JSON string
	new_metadata_json = json.dumps(existing_metadata)
	cursor.execute("UPDATE user_docs SET cost = cost + %s, metadata = %s WHERE chat_id = %s", (cost, new_metadata_json, chat_id))

	#cursor.execute("UPDATE user_docs SET cost = cost + %s WHERE chat_id = %s", (cost,chat_id))
	mysql.connection.commit()
	print(f"chat id updated : {chat_id}")
	if send_email_notification:
		# Send the email notification
		send_chatbot_created_email(user_id, chat_id)
		return jsonify({"success": True, "redirect": f"https://chatflux.io/chatbot/{chat_id}"})

	else:
		return jsonify({"success": True, "redirect": f"https://chatflux.io/chatbot/{chat_id}"})

#EMBED WEBSITE CONTENT
@app.route('/add_hyperlinks', methods=['POST'])
def add_hyperlinks():
	
	if not loggedin():
		return redirect(url_for('login'))
	# Check if the user can create a new chatbot
	if not can_create_chatbot(session['id']):
		msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
		flash(msg)
		return redirect(url_for('urlcreate'))
	# Check if the user can import data from websites based on their plan
	if not can_import_website_data(session['id']):
		msg = "Importing data from Websites is not allowed on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to unlock this feature."
		flash(msg)
		return redirect(url_for('urlcreate'))
	
	hyperlinks = request.get_json().get('links', [])
	print(hyperlinks)

	if not hyperlinks:
		print("not")
		msg = "Please provide at least one hyperlink."
		flash(msg)
		return redirect(url_for('urlcreate'))

	doc_id = uuid.uuid4()
	user_id = session['id']
	chat_id = f"{user_id}_{doc_id}"

	# Adding the chatbot build in progress feature
	# Here i will insert a row with chatbot id and set isReady column to 0
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name, cost, ready_status) VALUES (%s, %s, %s, %s, %s, %s)", 
		  (session['id'], '', chat_id, '', 0, False))
	mysql.connection.commit()
	# debug log with emoji fusée
	print(f"Chatbot {chat_id} is being built... 🔥")
	

	try:
		start_time = time.time()
		combined_text, url = sitefy(hyperlinks, session['id'])
		elapsed_time = time.time() - start_time

		if len(combined_text) <= 20 or combined_text == "":
			print(f"Elapsed time : {elapsed_time}")
			print(f"Content lenght : {len(combined_text)}")
			# Here i will delete the row with chatbot id
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute("DELETE FROM user_docs WHERE chat_id = %s", (chat_id,))
			mysql.connection.commit()
			# debug log with emoji bin
			print(f"Chatbot {chat_id} has been deleted... 🗑️")
			msg = "We could not find enough text on the provided website(s). Please try again with different website(s)."
			print(msg)
			flash(msg)
			return jsonify({"error": msg}), 400
		
		if elapsed_time > 60:
			# Set a flag to send an email notification
			send_email_notification = True
			user_id = session['id']
		else:
			send_email_notification = False
	except requests.exceptions.RequestException as e:
		print(f"Error with proxies : {e}")
		msg= "An error occured, please retry in a few seconds. If the error persist, please contact support@chatflux.io"
		flash(msg)

		# Here i will delete the row with chatbot id
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute("DELETE FROM user_docs WHERE chat_id = %s", (chat_id,))
		mysql.connection.commit()
		# debug log with emoji bin
		print(f"Chatbot {chat_id} has been deleted... 🗑️")

		return redirect(url_for('urlcreate'))

	text = text_to_docsv2(combined_text, url)

	cost = embed_docs2(text , chat_id, url)
	persist_directory = ""
	current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	# Prepare the metadata as a dictionary
	metadata = {
		"files": [
			{"file_name": url, "created_at": current_datetime}
		]
	}
	# Convert the metadata to a JSON string
	metadata_json = json.dumps(metadata)
	
	print("indexed ok")
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

	# Here i will update the row with chatbot id and set isReady column to 1 instead of inserting a new row
	cursor.execute("UPDATE user_docs SET document_name = %s, pickle_file_name = %s, cost = cost + %s, metadata = %s, ready_status = True WHERE chat_id = %s",
				(url, persist_directory, cost, metadata_json, chat_id))
	#debug log with emoji fusée
	print(f"Chatbot {chat_id} is ready... 🚀")
	
	mysql.connection.commit()

	print(f"chat id inserted : {chat_id}")
	if send_email_notification:
		# Send the email notification
		send_chatbot_created_email(user_id, chat_id)
		return jsonify({"success": True, "redirect": f"https://chatflux.io/chatbot/{chat_id}"})

	else:
		return jsonify({"success": True, "redirect": f"https://chatflux.io/chatbot/{chat_id}"})
	


def send_chatbot_created_email(user_id, chat_id):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve account info from database that's associated with the captured user id
	cursor.execute('SELECT * FROM accounts WHERE id = %s', (user_id,))
	account = cursor.fetchone()
	email_info = Message('Chatflux.io - Your chatbot has been created', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [account['email']])
	email_info.body = f"Your chatbot with ID {chat_id} has been created. You can now start using it. Visit https://chatflux.io/chatbot/{chat_id} to access your chatbot."
	mail.send(email_info)


#PLAN LIMITATION
def has_no_branding(chat_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT plans.no_branding
                      FROM accounts
                      JOIN plans ON accounts.plan_id = plans.id
                      JOIN user_docs ON accounts.id = user_docs.user_id
                      WHERE user_docs.chat_id = %s""", (chat_id,))
    result = cursor.fetchone()
    return result['no_branding'] == 1

@app.route('/chatbot-iframe', methods=['GET'])
def chatbot_iframe():

	chat_id = request.args.get('chatId', None)
	no_branding = False
	#
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM user_docs WHERE chat_id = %s ', (chat_id,))
	mychatbot = cursor.fetchone()
	
	# If chatbot exists
	if mychatbot:
		no_branding = has_no_branding(chat_id)
		return render_template('chatbot_iframe_dynamic.html', no_branding=no_branding , mychatbot=mychatbot)
	else:
		return redirect(url_for('index'))

def can_import_website_data(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.import_data_websites FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['import_data_websites'] == 1

def can_import_multiple_docs(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.import_multiple_docs FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['import_multiple_docs'] == 1

def can_create_chatbot(user_id):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT p.chatbot_limit FROM accounts a JOIN plans p ON a.plan_id = p.id WHERE a.id = %s", (user_id,))
	chatbot_limit = cursor.fetchone()['chatbot_limit']

	cursor.execute("SELECT COUNT(*) as chatbot_count FROM user_docs WHERE user_id = %s", (user_id,))
	chatbot_count = cursor.fetchone()['chatbot_count']

	if chatbot_limit == 0 or chatbot_count < chatbot_limit:
		return True
	else:
		return False
	
def can_import_youtube_data(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.import_data_youtube FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['import_data_youtube'] == 1

def can_create_api(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.api_access FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['api_access'] == 1

def can_suggest_messages(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.suggested_messages FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['suggested_messages'] == 1

def can_add_human_help(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.human_help FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['human_help'] == 1

def can_collect_leads(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.leads FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['leads'] == 1

def can_manage_metadata(user_id):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT plans.manage_metadata FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
	result = cursor.fetchone()
	return result['manage_metadata'] == 1

def can_customize_color(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.customized_appearance FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['customized_appearance'] == 1

def can_customize_greeting(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.customized_greeting FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['customized_greeting'] == 1

def can_customize_prompt(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT plans.customized_prompt FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (user_id,))
    result = cursor.fetchone()
    return result['customized_prompt'] == 1

@app.route('/fromtext/')
def fromtext():
	if not loggedin():
		return redirect(url_for('login'))
	can_upload_multiple = can_import_multiple_docs(session['id'])
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('fromtext.html', msg=msg)


@app.route('/updatetext/<chat_id>/')
def updatetextfront(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	can_upload_multiple = can_import_multiple_docs(session['id'])
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('updatetext.html',chat_id=chat_id, msg=msg)

#EMBED Text
@app.route('/uploadtext', methods=['POST'])
def uploadtext():
	try:
		if not loggedin():
			return redirect(url_for('login'))
		
		chatbot_text = request.form.get('chatbottext')
		
		# check if chatbot_text is not None and has more than 18 characters
		if chatbot_text and len(chatbot_text) > 5:
			# get the first 10 characters
			filename = chatbot_text[:5]+"..."
		else:
			# if the text is less than 18 characters, then use the whole text
			filename = chatbot_text

		doc_id = uuid.uuid4()
		user_id = session['id']
		chat_id = f"{user_id}_{doc_id}"
		
		
		start_time = time.time()

		text = text_to_docsv2(chatbot_text, filename)
		#text = text_to_docs(chatbot_text)

		plan_id = currentplan(user_id)

		# Check for plan_id and set the max characters accordingly.
		if plan_id == 1:
			MAX_CHARS = 100_000
		else:
			MAX_CHARS = 11_000_000

		total_chars = sum(len(doc.page_content) for doc in text)
		
		if total_chars > MAX_CHARS:
			print(f"File too large. This file is containing {total_chars} chars")
			flash(f'File too large. The maximum allowed size is {MAX_CHARS} character for your plan, butthe file contains {total_chars} characters.')
			return redirect(url_for('create'))
		

		if not can_create_chatbot(session['id']):
			msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
			flash(msg)
			return redirect(url_for('create'))
		
		try:			
			cost = embed_docs2(text, chat_id, filename)
			print("indexed ok")
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			persist_directory = ""
			
			current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			# Prepare the metadata as a dictionary
			metadata = {
				"files": [
					{"file_name": filename, "created_at": current_datetime}
				]
			}
			# Convert the metadata to a JSON string
			metadata_json = json.dumps(metadata)

			#cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name,cost) VALUES ( %s, %s, %s, %s, %s)", (session['id'], filename, chat_id, persist_directory,cost))
			cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name, cost, metadata) VALUES ( %s, %s, %s, %s, %s, %s)", 
		  (session['id'], filename, chat_id, persist_directory, cost, metadata_json))

			
			mysql.connection.commit()
			print(f"chat id inserted : {chat_id}")
			elapsed_time = time.time() - start_time
			if elapsed_time > 60:
				# Set a flag to send an email notification
				send_email_notification = True
				user_id = session['id']
			else:
				send_email_notification = False

				
			if send_email_notification:
				# Send the email notification
				send_chatbot_created_email(user_id, chat_id)
				return  redirect(url_for('chatbot', chat_id=chat_id))
			else:
				return  redirect(url_for('chatbot', chat_id=chat_id))
		
		except OpenAIError as e:
			return e._message
	except  Exception as e:
		print(e)



# Improving Chatbot Q&A
@app.route('/improvebot', methods=['POST'])
def improvebot():
	
	data = request.get_json()
	question = data['question']
	answer = data['answer']
	chatbot_id = data['chatbot_id']
	
	if not loggedin():
		return redirect(url_for('login'))

	# check if chatbot belongs to the user
	user_id = session['id']
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT * FROM user_docs WHERE chat_id = %s AND user_id = %s", (chatbot_id, user_id))
	chatbot = cursor.fetchone()

	if not chatbot:
		return jsonify({"error": "This chatbot does not belong to you."}), 400


	# validate the question and answer , continue if (should not be empty & should be max 500 chars each)
	if not question or not answer or len(question) > 500 or len(answer) > 500:
		return jsonify({"error": "Please provide a valid question and answer. The maximum allowed characters is 500."}), 400
	
	# fomat the question and answer
	qa = f"Q: {question}\nA: {answer}\n"

	# Set title
	title = f"Q:{question[:10]}... A:{answer[:10]}..."
	
	text = text_to_docsv2(qa, title)
	# update the chatbot	
	chatbot_id, cost = update_docs(text, chatbot_id, title)

	# metadata update
	update_metadata(chatbot_id, title, cost)
	print(f"[IMPROVE Q&A] : CHATBOT_ID : {chatbot_id} - Q&A : {qa}")
	return jsonify({"success": True, "message" : "Settings has been updated successfully. Redirecting to chatbot page now...","redirect": f"/chatbot/{chatbot_id}"})



	
def update_metadata(chatbot_id, filename, cost):
	"""Update the metadata of a chatbot."""

	current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	# Fetch the existing metadata
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT metadata FROM user_docs WHERE chat_id = %s", (chatbot_id,))
	row = cursor.fetchone()

	# Parse the existing metadata
	existing_metadata = json.loads(row['metadata']) if row and row['metadata'] else {"files": []}

	# Append new file to the metadata's "files" list
	existing_metadata["files"].append({"file_name": filename, "created_at": current_datetime})

	# Convert the metadata back to a JSON string
	new_metadata_json = json.dumps(existing_metadata)
	
	cursor.execute("UPDATE user_docs SET cost = cost + %s, metadata = %s WHERE chat_id = %s", (cost, new_metadata_json, chatbot_id))

	
	mysql.connection.commit()
	



#Update Text
@app.route('/updatetext', methods=['POST'])
def updatetext():
	try:
		if not loggedin():
			return redirect(url_for('login'))
		
		chatbot_text = request.form.get('chatbottext')
		
		# check if chatbot_text is not None and has more than 18 characters
		if chatbot_text and len(chatbot_text) > 5:
			# get the first 10 characters
			filename = chatbot_text[:5]+"..."
		else:
			# if the text is less than 18 characters, then use the whole text
			filename = chatbot_text

		doc_id = uuid.uuid4()
		user_id = session['id']
		chat_id = f"{user_id}_{doc_id}"
		
		
		start_time = time.time()

		text = text_to_docsv2(chatbot_text, filename)
		#text = text_to_docs(chatbot_text)

		plan_id = currentplan(user_id)

		# Check for plan_id and set the max characters accordingly.
		if plan_id == 1:
			MAX_CHARS = 100_000
		else:
			MAX_CHARS = 11_000_000
			
		total_chars = sum(len(doc.page_content) for doc in text)
		
		if total_chars > MAX_CHARS:
			print(f"File too large. This file is containing {total_chars} chars")
			flash(f'File too large. The maximum allowed size is {MAX_CHARS} character for your plan, butthe file contains {total_chars} characters.')
			return redirect(url_for('create'))
		

		if not can_create_chatbot(session['id']):
			msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
			flash(msg)
			return redirect(url_for('create'))
		
		try:			
			chat2update = request.form.get('chatid')			
			chat_id, cost = update_docs(text, chat2update, filename)
			sid = session['id'] 
			print("indexed ok")

			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			persist_directory = ""
			current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

			# Fetch the existing metadata
			cursor.execute("SELECT metadata FROM user_docs WHERE chat_id = %s", (chat_id,))
			row = cursor.fetchone()

			# Parse the existing metadata
			existing_metadata = json.loads(row['metadata']) if row and row['metadata'] else {"files": []}

			# Append new file to the metadata's "files" list
			existing_metadata["files"].append({"file_name": filename, "created_at": current_datetime})

			# Convert the metadata back to a JSON string
			new_metadata_json = json.dumps(existing_metadata)
			
			#cursor.execute("UPDATE user_docs SET cost = cost + %s WHERE chat_id = %s", (cost,chat_id))
			cursor.execute("UPDATE user_docs SET cost = cost + %s, metadata = %s WHERE chat_id = %s", (cost, new_metadata_json, chat_id))

			
			mysql.connection.commit()
			print(f"chat id inserted : {chat_id}")
			elapsed_time = time.time() - start_time
			if elapsed_time > 60:
				# Set a flag to send an email notification
				send_email_notification = True
				user_id = session['id']
			else:
				send_email_notification = False

				
			if send_email_notification:
				# Send the email notification
				send_chatbot_created_email(user_id, chat_id)
				return  redirect(url_for('chatbot', chat_id=chat_id))
			else:
				return  redirect(url_for('chatbot', chat_id=chat_id))
		
		except OpenAIError as e:
			return e._message
	except  Exception as e:
		print(e)

#EMBED DOCUMENTS
@app.route('/upload', methods=['POST'])
def upload():
	try:
		if not loggedin():
			return redirect(url_for('login'))

		if 'files[]' not in request.files:
			return "No files found in the request", 400

		uploaded_files = request.files.getlist('files[]')
		merged_text = []

		doc_id = uuid.uuid4()
		user_id = session['id']
		chat_id = f"{user_id}_{doc_id}"
		
		
		start_time = time.time()

		for file in uploaded_files:
			filename = file.filename
			# Handle uploaded file based on file extension
			if filename.endswith(".pdf"):
				try:
					doc = parse_pdf(file)
				except ValueError as e:  # Catch the exception 
					flash(str(e))
					return redirect(url_for('create'))
			elif filename.endswith(".docx"):
				doc = parse_docx(file)
			elif filename.endswith(".csv"):
				doc = parse_csv(file)
			elif filename.endswith(".txt"):
				doc = parse_txt(file)
			else:
				doc = None
				return "File type not supported"
			print("parsed")

			text = text_to_docsv2(doc, filename)
			merged_text.extend(text)

			plan_id = currentplan(user_id)

			# Check for plan_id and set the max characters accordingly.
			if plan_id == 1:
				MAX_CHARS = 100_000
			else:
				MAX_CHARS = 11_000_000

			total_chars = sum(len(doc.page_content) for doc in merged_text)
			
			if total_chars > MAX_CHARS:
				print(f"File too large. This file is containing {total_chars} chars")
				flash(f'File too large. The maximum allowed size is {MAX_CHARS} character for your plan, butthe file contains {total_chars} characters.')
				return redirect(url_for('create'))
		

		if not can_create_chatbot(session['id']):
			msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
			flash(msg)
			return redirect(url_for('create'))
		
		try:			
			cost = embed_docs2(text, chat_id, filename)
			print("indexed ok")
			
			current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			# Prepare the metadata as a dictionary
			metadata = {
				"files": [
					{"file_name": filename, "created_at": current_datetime}
				]
			}
			# Convert the metadata to a JSON string
			metadata_json = json.dumps(metadata)

			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			persist_directory = ""
			
			#cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name,cost) VALUES ( %s, %s, %s, %s, %s)", (session['id'], filename, chat_id, persist_directory,cost))
			cursor.execute("INSERT INTO user_docs (user_id, document_name, chat_id, pickle_file_name, cost, metadata) VALUES ( %s, %s, %s, %s, %s, %s)", 
		  (session['id'], filename, chat_id, persist_directory, cost, metadata_json))

			
			mysql.connection.commit()
			print(f"chat id inserted : {chat_id}")
			elapsed_time = time.time() - start_time
			if elapsed_time > 60:
				# Set a flag to send an email notification
				send_email_notification = True
				user_id = session['id']
			else:
				send_email_notification = False

				
			if send_email_notification:
				# Send the email notification
				send_chatbot_created_email(user_id, chat_id)
				return  redirect(url_for('chatbot', chat_id=chat_id))
			else:
				return  redirect(url_for('chatbot', chat_id=chat_id))
		
		except OpenAIError as e:
			return e._message
	except  Exception as e:
		print(e)

# UPDATE WITH DOCUMENTS
@app.route('/updatedocument', methods=['POST'])
def updatedocument():
	try:
		if not loggedin():
			return redirect(url_for('login'))

		if 'files[]' not in request.files:
			return "No files found in the request", 400

		uploaded_files = request.files.getlist('files[]')
		merged_text = []
		
		user_id = session['id']

		start_time = time.time()

		for file in uploaded_files:
			filename = file.filename
			# Handle uploaded file based on file extension
			if filename.endswith(".pdf"):
				try:
					doc = parse_pdf(file)
				except ValueError as e:  # Catch the exception 
					flash(str(e))
					return redirect(url_for('create'))
			elif filename.endswith(".docx"):
				doc = parse_docx(file)
			elif filename.endswith(".csv"):
				doc = parse_csv(file)
			elif filename.endswith(".txt"):
				doc = parse_txt(file)
			else:
				doc = None
				return "File type not supported"
			print("parsed")

			text = text_to_docsv2(doc, filename)

			merged_text.extend(text)

			plan_id = currentplan(user_id)

			# Check for plan_id and set the max characters accordingly.
			if plan_id == 1:
				MAX_CHARS = 100_000
			else:
				MAX_CHARS = 11_000_000

			total_chars = sum(len(doc.page_content) for doc in merged_text)
			
			if total_chars > MAX_CHARS:
				print(f"File too large. This file is containing {total_chars} chars")
				flash(f'File too large. The maximum allowed size is {MAX_CHARS} character for your plan, butthe file contains {total_chars} characters.')
				return redirect(url_for('create'))
		

		if not can_create_chatbot(session['id']):
			msg = "You have reached the chatbot limit on your current plan. Please <a class='font-bold' href='https://chatflux.io/pricing' target='_blank'>upgrade your plan</a> to create more chatbots."
			flash(msg)
			return redirect(url_for('create'))
		
		try:
			
			chat2update = request.form.get('chatid')			
			chat_id, cost = update_docs(text, chat2update, filename)
			sid = session['id'] 
			print("indexed ok")
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			persist_directory = ""
			
			current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

			# Fetch the existing metadata
			cursor.execute("SELECT metadata FROM user_docs WHERE chat_id = %s", (chat_id,))
			row = cursor.fetchone()

			# Parse the existing metadata
			existing_metadata = json.loads(row['metadata']) if row and row['metadata'] else {"files": []}

			# Append new file to the metadata's "files" list
			existing_metadata["files"].append({"file_name": filename, "created_at": current_datetime})

			# Convert the metadata back to a JSON string
			new_metadata_json = json.dumps(existing_metadata)
			
			#cursor.execute("UPDATE user_docs SET cost = cost + %s WHERE chat_id = %s", (cost,chat_id))
			cursor.execute("UPDATE user_docs SET cost = cost + %s, metadata = %s WHERE chat_id = %s", (cost, new_metadata_json, chat_id))

			
			mysql.connection.commit()
			print(f"chat id inserted : {chat_id}")
			elapsed_time = time.time() - start_time
			if elapsed_time > 60:
				# Set a flag to send an email notification
				send_email_notification = True
				user_id = session['id']
			else:
				send_email_notification = False

				
			if send_email_notification:
				# Send the email notification
				send_chatbot_created_email(user_id, chat_id)
				return  redirect(url_for('chatbot', chat_id=chat_id))
			else:
				return  redirect(url_for('chatbot', chat_id=chat_id))
		
		except OpenAIError as e:
			return e._message
	except  Exception as e:
		print(e)




@app.route('/updatedocuments/<chat_id>/')
def updatedocuments(chat_id):
	if not loggedin():
		return redirect(url_for('login'))
	can_upload_multiple = can_import_multiple_docs(session['id'])
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('updatedoc.html',chat_id=chat_id, can_upload_multiple=can_upload_multiple, msg=msg)


@app.route('/create/')
def create():
	if not loggedin():
		return redirect(url_for('login'))
	can_upload_multiple = can_import_multiple_docs(session['id'])
	msg=""
	msg = get_flashed_messages()
	msg = ', '.join(msg) if msg else ''  # join messages if there are any
	return render_template('upload2.html', can_upload_multiple=can_upload_multiple, msg=msg)

#landing
@app.route('/')
def index():
	return render_template('index.html')



# http://localhost:5000/ - this will be the login page, we need to use both GET and POST requests
@app.route('/login', methods=['GET', 'POST'])
def login():
	# Redirect user to home page if logged-in
	if loggedin():
		return redirect(url_for('mychatbots'))
	# Output message if something goes wrong...
	msg = ''
	# Retrieve the settings
	settings = get_settings()
	# Check if "username" and "password" POST requests exist (user submitted form)
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'token' in request.form:
		# Bruteforce protection
		login_attempts_res = login_attempts(False)
		if settings['brute_force_protection']['value'] == 'true' and login_attempts_res and login_attempts_res['attempts_left'] <= 1:
			return 'You cannot login right now! Please try again later!'
		# Create variables for easy access
		username = request.form['username']
		password = request.form['password']
		token = request.form['token']
		# Retrieve the hashed password
		hash = password + app.secret_key
		hash = hashlib.sha1(hash.encode())
		password = hash.hexdigest();
		# Check if account exists	a& using MySQL
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
		# Fetch one record and return result
		account = cursor.fetchone()
		ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
		# If account exists in accounts table in out database
		if account:
			# Check if account is activated
			if settings['account_activation']['value'] == 'true' and account['activation_code'] != 'activated' and account['activation_code'] != '':
				return 'Please activate your account to login!'
			# CSRF protection, form token should match the session token
			if settings['csrf_protection']['value'] == 'true' and str(token) != str(session['token']):
				return 'Invalid token!'
			# Two-factor
			if settings['twofactor_protection']['value'] == 'true' and account['ip'] != ip:
				session['tfa_id'] = account['id']
				session['tfa_email'] = account['email']
				return 'tfa: twofactor'
			# Create session data, we can access this data in other routes
			session['loggedin'] = True
			session['id'] = account['id']
			session['username'] = account['username']
			session['role'] = account['role']
			# Reset the attempts left
			cursor.execute('DELETE FROM login_attempts WHERE ip_address = %s', (ip,))
			mysql.connection.commit()
			# If the user checked the remember me checkbox...
			if 'rememberme' in request.form:
				rememberme_code = account['rememberme']
				if not rememberme_code:
					# Create hash to store as cookie
					rememberme_code = account['username'] + request.form['password'] + app.secret_key
					rememberme_code = hashlib.sha1(rememberme_code.encode())
					rememberme_code = rememberme_code.hexdigest()
				# the cookie expires in 90 days
				expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
				resp = make_response('Success', 200)
				resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
				# Update rememberme in accounts table to the cookie hash
				cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, account['id'],))
				mysql.connection.commit()
				# Return response
				return resp
			return 'Success'
		else:
			# Account doesnt exist or username/password incorrect
			if settings['brute_force_protection']['value'] == 'true':
				# Bruteforce protection enabled - update attempts left
				login_attempts_res = login_attempts();
				return 'Your login details seem to be incorrect. Please try again. You have ' + str(login_attempts_res['attempts_left']) + ' attempts remaining!'
			else:
				return 'Your login details seem to be incorrect. Please try again.'
	# Generate random token that will prevent CSRF attacks
	token = uuid.uuid4()
	session['token'] = token
	# Show the login form with message (if any)
	return render_template('login.html', msg=msg, token=token, settings=settings)


# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register/', methods=['GET', 'POST'])
def register():
	ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
	# Redirect user to home page if logged-in
	if loggedin():
		return redirect(url_for('mychatbots'))
	# Output message variable
	msg = ''
	# Retrieve the settings
	settings = get_settings()
	# Check if "username", "password", "cpassword" and "email" POST requests exist (user submitted form)
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'cpassword' in request.form and 'email' in request.form:
		# Create variables for easy access
		username = request.form['username']
		password = request.form['password']
		cpassword = request.form['cpassword']
		email = request.form['email']
		role = 'Member'
		# Hash the password
		hash = password + app.secret_key
		hash = hashlib.sha1(hash.encode())
		hashed_password = hash.hexdigest();
		# Check if account exists using MySQL
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
		account = cursor.fetchone()
		# reCAPTCHA
		if settings['recaptcha']['value'] == 'true':
			if 'g-recaptcha-response' not in request.form:
				return 'Invalid captcha!'
			req = urllib.request.Request('https://www.google.com/recaptcha/api/siteverify', urllib.parse.urlencode({ 'response': request.form['g-recaptcha-response'], 'secret': settings['recaptcha_secret_key']['value'] }).encode())	
			response_json = json.loads(urllib.request.urlopen(req).read().decode())
			if not response_json['success']:
				return 'Invalid captcha!'
		# Validation
		if account:
			return 'Account already exists!'
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			return 'Invalid email address!'
		elif not re.match(r'^[A-Za-z0-9]+$', username):
			return 'Username must contain only characters and numbers!'
		elif not username or not password or not cpassword or not email:
			return 'Please fill out the form!'
		elif password != cpassword:
			return 'Passwords do not match!'
		elif len(username) < 5 or len(username) > 20:
			return 'Username must be between 5 and 20 characters long!'
		elif len(password) < 5 or len(password) > 20:
			return 'Password must be between 5 and 20 characters long!'
		elif settings['account_activation']['value'] == 'true':
			# Account activation enabled
			# Generate a random unique id for activation code
			activation_code = uuid.uuid4()
			# Insert account into database
			cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (%s, %s, %s, %s, %s, %s)', (username, hashed_password, email, activation_code, role, ip,))
			mysql.connection.commit()
			# Create new message
			email_info = Message('Account Activation Required', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [email])
			# Activate Link URL
			activate_link = app.config['DOMAIN'] + url_for('activate', email=email, code=str(activation_code))
			# Define and render the activation email template
			email_info.body = render_template('activation-email-template.html', link=activate_link)
			email_info.html = render_template('activation-email-template.html', link=activate_link)
			# send activation email to user
			mail.send(email_info)
			# Output message
			return 'Please check your email to activate your account!'
		else:
			# Account doesnt exists and the form data is valid, now insert new account into accounts table
			cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (%s, %s, %s, "activated", %s, %s)', (username, hashed_password, email, role, ip,))
			mysql.connection.commit()
			# Auto login if the setting is enabled
			if settings['auto_login_after_register']['value'] == 'true':
				session['loggedin'] = True
				session['id'] = cursor.lastrowid
				session['username'] = username
				session['role'] = role
				
				rememberme_code = username + email + app.secret_key
				rememberme_code = hashlib.sha1(rememberme_code.encode())
				rememberme_code = rememberme_code.hexdigest()
				# The cookie expires in 90 days
				expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
				resp = make_response(redirect(url_for('mychatbots')))
				resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
				# Update rememberme in accounts table to the cookie hash
				cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, session['id'],))
				mysql.connection.commit()
				cursor.close()

				return 'autologin'
			# Output message
			return 'You have registered! You can now login!'
	elif request.method == 'POST':
		# Form is empty... (no POST data)
		return 'Please fill out the form!'
	# Render registration form with message (if any)
	return render_template('register.html', msg=msg, settings=settings)

# http://localhost:5000/pythinlogin/activate/<email>/<code> - this page will activate a users account if the correct activation code and email are provided
@app.route('/activate/<string:email>/<string:code>', methods=['GET'])
def activate(email, code):
	# Output message variable
	msg = 'Account doesn\'t exist with that email or the activation code is incorrect!'
	# Check if the email and code provided exist in the accounts table
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM accounts WHERE email = %s AND activation_code = %s', (email, code,))
	account = cursor.fetchone()
	# If account exists
	if account:
		# account exists, update the activation code to "activated"
		cursor.execute('UPDATE accounts SET activation_code = "activated" WHERE email = %s AND activation_code = %s', (email, code,))
		mysql.connection.commit()
		# automatically log the user in and redirect to the home page
		session['loggedin'] = True
		session['id'] = account['id']
		session['username'] = account['username']
		session['role'] = account['role']
		# Redirect to home page
		return redirect(url_for('mychatbots'))
	# Render activation template
	return render_template('activate.html', msg=msg)


# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/profile/')
def profile():
	# Check if user is loggedin
	if loggedin():
		# Retrieve all account info from the database
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
		account = cursor.fetchone()
		#FETCH APPSUMO TOKEN INFO :
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM appsumo_tokens WHERE activation_email = %s', (account['email'],))
		appsumo = cursor.fetchone()
		#GETING COUNT FOR USER
		cursor.execute("SELECT SUM(interaction_count) as count FROM chatbot_interactions WHERE user_id = %s", (session['id'],))
		interaction_count_result = cursor.fetchone()
		interaction_count = interaction_count_result['count'] if interaction_count_result['count'] else 0
		#GETTING LIMIT
		cursor.execute("SELECT accounts.plan_id, plans.chatbot_interaction_limit FROM accounts JOIN plans ON accounts.plan_id = plans.id WHERE accounts.id = %s", (session['id'],))
		plan_info = cursor.fetchone()
		interaction_limit = plan_info['chatbot_interaction_limit']
		if interaction_limit == 0:
			interaction_limit = "∞"
		#CHATBOT LIMIT
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute("SELECT p.chatbot_limit FROM accounts a JOIN plans p ON a.plan_id = p.id WHERE a.id = %s", (session['id'],))
		chatbot_limit = cursor.fetchone()['chatbot_limit']
		if chatbot_limit == 0:
			chatbot_limit = "∞"
		#CHATBOT COUNT
		cursor.execute("SELECT COUNT(*) as chatbot_count FROM user_docs WHERE user_id = %s", (session['id'],))
		chatbot_count = cursor.fetchone()['chatbot_count']
		#API USAGE
		cursor.execute("SELECT SUM(api_usage) as count FROM api_keys WHERE user_id = %s", (session['id'],))
		api_count_result = cursor.fetchone()
		api = api_count_result['count'] if api_count_result['count'] else 0
		#PLAN NAMES
		plan_names = {
        1: 'Explorer',
        2: 'Adventurer',
        3: 'Conqueror',
        4: 'The sky is the limit',
		5: 'AppSumo Tier 1',
		6: 'AppSumo Tier 2',
		7: 'AppSumo Tier 3'
    	}
		# Render the profile page along with the account info
		return render_template('profile.html', appsumo=appsumo, api=api, chatbot_count=chatbot_count, chatbot_limit=chatbot_limit, interaction_count=interaction_count, interaction_limit=interaction_limit, plan_names=plan_names, account=account, role=session['role'])
	# User is not loggedin, redirect to login page
	return redirect(url_for('login'))

# # http://localhost:5000/pythinlogin/profile/edit - user can edit their existing details
# @app.route('/profile/edit/', methods=['GET', 'POST'])
# def edit_profile():
# 	# Check if user is loggedin
# 	if loggedin():
# 		# Output message
# 		msg = ''
# 		# Retrieve the settings
# 		settings = get_settings()
# 		# We need to retieve additional account info from the database and populate it on the profile page
# 		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 		cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
# 		account = cursor.fetchone()
# 		# Check if "username", "password" and "email" POST requests exist (user submitted form)
# 		if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
# 			# Create variables for easy access
# 			username = request.form['username']
# 			password = request.form['password']
# 			cpassword = request.form['cpassword']
# 			email = request.form['email']
# 			# Retrieve account by the username
# 			cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
# 			new_account = cursor.fetchone()
# 			# validation check
# 			if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
# 				msg = 'Invalid email address!'
# 			elif not re.match(r'[A-Za-z0-9]+', username):
# 				msg = 'Username must contain only characters and numbers!'
# 			elif not username or not email:
# 				msg = 'Please fill out the form!'
# 			elif session['username'] != username and new_account:
# 				msg = 'Username already exists!'
# 			elif len(username) < 5 or len(username) > 20:
# 				msg = 'Username must be between 5 and 20 characters long!'
# 			elif password and (len(password) < 5 or len(password) > 20):
# 				msg = 'Password must be between 5 and 20 characters long!'
# 			elif password != cpassword:
# 				msg = 'Passwords do not match!'
# 			else:
# 				# Determine password
# 				current_password = account['password']
# 				# If new password provided
# 				if password:
# 					# Hash the password
# 					hash = password + app.secret_key
# 					hash = hashlib.sha1(hash.encode())
# 					current_password = hash.hexdigest();
# 				# update account with the new details
# 				cursor.execute('UPDATE accounts SET username = %s, password = %s, email = %s WHERE id = %s', (username, current_password, email, session['id'],))
# 				mysql.connection.commit()
# 				# Update session variables
# 				session['username'] = username
# 				session['email'] = email
# 				# retrieve updated acount
# 				cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
# 				account = cursor.fetchone()
# 				# Reactivate account if account acivation option enabled
# 				if settings['account_activation']['value'] == 'true':
# 					# Generate a random unique id for activation code
# 					activation_code = uuid.uuid4()
# 					# Update activation code in database
# 					cursor.execute('UPDATE accounts SET activation_code = %s WHERE id = %s', (activation_code, session['id'],))
# 					mysql.connection.commit()
# 					# Create new message
# 					email_info = Message('Account Activation Required', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [email])
# 					# Activate Link URL
# 					activate_link = app.config['DOMAIN'] + url_for('activate', email=email, code=str(activation_code))
# 					# Define and render the activation email template
# 					email_info.body = render_template('activation-email-template.html', link=activate_link)
# 					email_info.html = render_template('activation-email-template.html', link=activate_link)
# 					# send activation email to user
# 					mail.send(email_info)
# 					# Output message
# 					msg = 'You have changed your email address! You need to re-activate your account! You will be automatically logged-out.'
# 				else:
# 					# Output message
# 					msg = 'Account updated successfully!'
# 		# Render the profile page along with the account info
# 		return render_template('profile-edit.html', account=account, role=session['role'], msg=msg)
# 	# Redirect to the login page
# 	return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/forgotpassword - user can use this page if they have forgotten their password
@app.route('/forgotpassword/', methods=['GET', 'POST'])
def forgotpassword():
	msg = ''
	# If forgot password form submitted
	if request.method == 'POST' and 'email' in request.form:
		# Capture input email
		email = request.form['email']
		# Define the connection cursor
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		# Retrieve account info from database that's associated with the captured email
		cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
		account = cursor.fetchone()
		# If account exists
		if account:
			# Generate unique reset ID
			reset_code = uuid.uuid4()
			# Update the reset column in the accounts table to reflect the generated ID
			cursor.execute('UPDATE accounts SET reset = %s WHERE email = %s', (reset_code, email,))
			mysql.connection.commit()
			# Create new email message
			email_info = Message('Password Reset', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [email])
			# Generate reset password link
			reset_link = app.config['DOMAIN'] + url_for('resetpassword', email = email, code = str(reset_code))
			# Email content
			email_info.body = 'Hello,' + account['username']+' Please click the following link to reset your password: ' + str(reset_link)
			email_info.html = '<p>Hello, ' + account['username']+' <br>Please click the following link to reset your password: <a href="' + str(reset_link) + '">' + str(reset_link) + '</a></p>'
			# Send mail
			mail.send(email_info)
			msg = 'Reset password link has been sent to your email'
		else:
			msg = 'An error occured, please recheck your email'
	# Render the forgot password template
	return render_template('forgotpassword.html', msg=msg)

# http://localhost:5000/pythinlogin/resetpassword/EMAIL/CODE - proceed to reset the user's password
@app.route('/resetpassword/<string:email>/<string:code>', methods=['GET', 'POST'])
def resetpassword(email, code):
	msg = ''
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve the account with the email and reset code provided from the GET request
	cursor.execute('SELECT * FROM accounts WHERE email = %s AND reset = %s', (email, code,))
	account = cursor.fetchone()
	# If account exists
	if account:
		# Check if the new password fields were submitted
		if request.method == 'POST' and 'npassword' in request.form and 'cpassword' in request.form:
			npassword = request.form['npassword']
			cpassword = request.form['cpassword']
			#pass should be more than 5 charch
			if len(npassword) < 5 or len(npassword) > 20:
				msg='Username must be between 5 and 20 characters long!'
			else:
				# Password fields must match
				if npassword == cpassword and npassword != "":
				# Hash new password
					hash = npassword + app.secret_key
					hash = hashlib.sha1(hash.encode())
					npassword = hash.hexdigest()
					# Update the user's password
					cursor.execute('UPDATE accounts SET password = %s, reset = "" WHERE email = %s', (npassword, email,))
					mysql.connection.commit()
					msg = 'Your password has been reset, you can now <a class="text-primary  hover:underline" href="' + url_for('login') + '">login</a>'
				else:
					msg = 'Passwords must match and must not be empty!'
		# Render the reset password template
		return render_template('resetpassword.html', msg=msg, email=email, code=code)
	return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/twofactor - two-factor authentication
@app.route('/twofactor/', methods=['GET', 'POST'])
def twofactor():
	# Output message
	msg = ''
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Verify the ID and email provided
	if 'tfa_email' in session and 'tfa_id' in session:
		# Retrieve the account
		cursor.execute('SELECT * FROM accounts WHERE id = %s AND email = %s', (session['tfa_id'], session['tfa_email'],))
		account = cursor.fetchone()
		# If account exists
		if account:
			# If the code param exists in the POST request form
			if request.method == 'POST' and 'code' in request.form:
				# If the user entered the correct code
				if request.form['code'] == account['tfa_code']:
					# Get the user's IP address
					ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
					# ip = request.environ['REMOTE_ADDR']
					# Update IP address in database
					cursor.execute('UPDATE accounts SET ip = %s WHERE id = %s', (ip, account['id'],))
					mysql.connection.commit()
					# Clear TFA session variables
					session.pop('tfa_email')
					session.pop('tfa_id')
					# Authenticate the user
					session['loggedin'] = True
					session['id'] = account['id']
					session['username'] = account['username']
					session['role'] = account['role']
					# Redirect to home page
					return redirect(url_for('mychatbots'))
				else:
					msg = 'Incorrect code provided!'
			else:
				# Generate unique code
				code = str(uuid.uuid4()).upper()[:5]
				# Update code in database
				cursor.execute('UPDATE accounts SET tfa_code = %s WHERE id = %s', (code, account['id'],))
				mysql.connection.commit()
				# Create new message
				email_info = Message('Your Access Code', sender = app.config['MAIL_DEFAULT_SENDER'], recipients = [account['email']])
				# Define and render the twofactor email template
				email_info.body = render_template('twofactor-email-template.html', code=code)
				email_info.html = render_template('twofactor-email-template.html', code=code)
				# send twofactor email to user
				mail.send(email_info)
		else:
			msg = 'No email and/or ID provided!'
	else:
		msg = 'No email and/or ID provided!'
	# Render twofactor template
	return render_template('twofactor.html', msg=msg)

def login_attempts(update = True):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Get the user's IP address
	ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
	# Get the current date
	now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	# Update attempts left
	if update:
		cursor.execute('INSERT INTO login_attempts (ip_address, `date`) VALUES (%s,%s) ON DUPLICATE KEY UPDATE attempts_left = attempts_left - 1, `date` = VALUES(`date`)', (ip, str(now),))
		mysql.connection.commit()
	# Retrieve the login attemmpts
	cursor.execute('SELECT * FROM login_attempts WHERE ip_address = %s', (ip,))
	login_attempts = cursor.fetchone()
	if login_attempts:
		# The date the attempts left expires (removed from database)
		expire = datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') + datetime.timedelta(days=1)
		# If current date is greater than expiration date
		if datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') > expire:
			# Delete the entry
			cursor.execute('DELETE FROM login_attempts WHERE id_address = %s', (ip,))
			mysql.connection.commit()
			login_attempts = []
	return login_attempts

# http://localhost:5000/pythinlogin/logout - this will be the logout page
@app.route('/logout/')
def logout():
	# Remove session data, this will log the user out
	session.pop('loggedin', None)
	session.pop('id', None)
	session.pop('username', None)
	session.pop('role', None)
	# Remove cookie data "remember me"
	resp = make_response(redirect(url_for('login')))
	resp.set_cookie('rememberme', expires=0)
	session.clear()
	return resp

@app.route("/glogin/")
def glogin():
	state = secrets.token_hex(16)
	authorization_url, _ = flow.authorization_url(state=state)
	session["state"] = state
	return redirect(authorization_url)

@app.route("/callback")
def callback():
	if loggedin():
		return redirect(url_for('mychatbots'))
	# Output message variable
	msg = ''
	# Retrieve the settings
	settings = get_settings()

	error = request.args.get('error')
	if error:
		msg = 'An Error Occured.'
		return msg

	request_state = request.args.get("state")
	session_state = session.get("state")

	if request_state is None or session_state is None or request_state != session_state:
		msg = 'An Error Occured. Please retry in a few seconds...'
		return render_template('login.html', msg=msg)

	flow.fetch_token(authorization_response=request.url)
		
	credentials = flow.credentials
	request_session = requests.session()
	cached_session = cachecontrol.CacheControl(request_session)
	token_request = google.auth.transport.requests.Request(session=cached_session)

	id_info = id_token.verify_oauth2_token(
		id_token=credentials._id_token,
		request=token_request,
		audience=GOOGLE_CLIENT_ID
	)
	#GOOGLE GAL OK
	session["google_id"] = id_info.get("sub")
	session["email"] = id_info.get("email")
	email = session["email"]
	print(email)
	
	# Check if account exists using MySQL
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
	account = cursor.fetchone()

	# ila kan deja hna
	if account:
		session['loggedin'] = True
		session['id'] = account['id']
		session['username'] = account['username']
		session['role'] = account['role']

		# If the account exists, we set rememberme by default
		rememberme_code = account['rememberme']
		if not rememberme_code:
			# Create hash to store as cookie
			rememberme_code = account['username'] + email + app.secret_key
			rememberme_code = hashlib.sha1(rememberme_code.encode())
			rememberme_code = rememberme_code.hexdigest()
			
		# The cookie expires in 90 days
		expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
		resp = make_response(redirect(url_for('mychatbots')))
		resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
		# Update rememberme in accounts table to the cookie hash
		cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, account['id'],))
		mysql.connection.commit()
		# Return response
		return resp
		
	
	#+ Logged in kada

	
	user = email.split('@')
	username = user[0]+"-"+str(random.randint(10, 99))
	session["username"] = username
	characters = string.ascii_letters + string.digits + string.punctuation
	rand_passwordnothash = ''.join(random.choice(characters) for i in range(12))
	hash = rand_passwordnothash + app.secret_key
	hash = hashlib.sha1(hash.encode())
	rand_password = hash.hexdigest();
	role = 'Member'
	ip = request.headers.get('CF-Connecting-IP', request.headers.get('X-Forwarded-For', request.remote_addr))
	cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (%s, %s, %s, "activated", %s, %s)', (username, rand_password, email, role, ip,))
	mysql.connection.commit()
	# Auto login if the setting is enabled
	if settings['auto_login_after_register']['value'] == 'true':
		session['loggedin'] = True
		session['id'] = cursor.lastrowid
		session['username'] = username
		session['role'] = role

		rememberme_code = username + email + app.secret_key
		rememberme_code = hashlib.sha1(rememberme_code.encode())
		rememberme_code = rememberme_code.hexdigest()
		# The cookie expires in 90 days
		expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
		resp = make_response(redirect(url_for('mychatbots')))
		resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
		# Update rememberme in accounts table to the cookie hash
		cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, session['id'],))
		mysql.connection.commit()
		# Return response
		return resp
	
		# # Return response
		# return redirect(url_for('mychatbots'))
		# Output message
	return 'You have registered! You can now login!'
	# Render registration form with message (if any)
	
	
# Check if logged in function, update session if cookie for "remember me" exists
def loggedin():
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Check if user is logged-in
	
	if 'google_id' in session:
		# Update last seen date
		cursor.execute('SELECT * FROM accounts WHERE email = %s', (session['email'],))
		iddb = cursor.fetchone()
		session['id'] = iddb['id']
		session['loggedin'] = True
		session['username'] = iddb['username']
		session['role'] = iddb['role']
		
		cursor.execute('UPDATE accounts SET last_seen = NOW() WHERE email = %s',  (session['email'],))
		mysql.connection.commit()
		return True
	if 'loggedin' in session:
		# Update last seen date
		cursor.execute('UPDATE accounts SET last_seen = NOW() WHERE id = %s', (session['id'],))
		mysql.connection.commit()
		return True
	elif 'rememberme' in request.cookies:
		# check if remembered, cookie has to match the "rememberme" field
		cursor.execute('SELECT * FROM accounts WHERE rememberme = %s', (request.cookies['rememberme'],))
		account = cursor.fetchone()
		if account:
			# update session variables
			session['loggedin'] = True
			session['id'] = account['id']
			session['username'] = account['username']
			session['role'] = account['role']
			return True
	# account not logged in return false
	return False

# ADMIN PANEL
# http://localhost:5000/admin/ - admin dashboard, view new accounts, active accounts, statistics
@app.route('/admin/', methods=['GET', 'POST'])
def admin():
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Retrieve new accounts for the current date
	cursor.execute('SELECT * FROM accounts WHERE cast(registered as DATE) = cast(now() as DATE) ORDER BY registered DESC')
	accounts = cursor.fetchall()
	# Get the total number of accounts
	cursor.execute('SELECT COUNT(*) AS total FROM user_docs')
	chatbots = cursor.fetchone()
	# Get the total number of accounts
	cursor.execute('SELECT COUNT(*) AS total FROM accounts')
	accounts_total = cursor.fetchone()
	# Get the total number of active accounts (<1 month)
	cursor.execute('SELECT COUNT(*) AS total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month)')
	inactive_accounts = cursor.fetchone()
	# Retrieve accounts created within 1 day from the current date
	cursor.execute('SELECT * FROM accounts WHERE last_seen > date_sub(now(), interval 1 day) ORDER BY last_seen DESC')
	active_accounts = cursor.fetchall()
	# Get the total number of inactive accounts
	cursor.execute('SELECT COUNT(*) AS total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month)')
	active_accounts2 = cursor.fetchone()
	# Render admin dashboard template
	plan_names = {
        1: 'Explorer',
        2: 'Adventurer',
        3: 'Conqueror',
        4: 'The sky is the limit',
		5: 'AppSumo Tier 1',
		6: 'AppSumo Tier 2',
		7: 'AppSumo Tier 3'
    }
	return render_template('admin/dashboard.html', plan_names=plan_names, accounts=accounts, selected='dashboard', selected_child='view', accounts_total=accounts_total['total'], inactive_accounts=inactive_accounts['total'], active_accounts=active_accounts, active_accounts2=active_accounts2['total'], chatbots=chatbots['total'] ,time_elapsed_string=time_elapsed_string)

# http://localhost:5000/admin/chats - view all chats
@app.route('/admin/chats/<string:msg>/<string:search>/<string:order>/<string:order_by>/<int:page>', methods=['GET', 'POST'])
@app.route('/admin/chats/', methods=['GET', 'POST'], defaults={ 'msg': '','search' : '', 'order': 'DESC', 'order_by': '', 'page': 1})
def admin_chats(msg, search, order, order_by, page):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Params validation
	msg = '' if msg == 'n0' else msg
	search = '' if search == 'n0' else search
	order = 'DESC' if order == 'DESC' else 'ASC'
	order_by_whitelist = ['id', 'user_id', 'document_name', 'chat_id', 'pickle_file_name', 'cost','public']
	order_by = order_by if order_by in order_by_whitelist else 'id'
	results_per_page = 20
	param1 = (page - 1) * results_per_page
	param2 = results_per_page
	param3 = '%' + search + '%'
	# SQL where clause
	where = ''; #username / email -!
	where += 'WHERE (document_name LIKE %s OR chat_id LIKE %s) ' if search else ''	
	# Params array and append specified params
	params = []
	if search:
		params.append(param3)
		params.append(param3)
	# Fetch the total number of accounts
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT COUNT(*) AS total FROM user_docs ' + where, params)
	accounts_total = cursor.fetchone()
	# Append params to array
	params.append(param1)
	params.append(param2)
	# Retrieve all accounts from the database
	cursor.execute('SELECT * FROM user_docs ' + where + ' ORDER BY ' + order_by + ' ' + order + ' LIMIT %s,%s', params)
	accounts = cursor.fetchall()
	# Determine the URL
	url = url_for('admin_chats') + '/n0/' + (search if search else 'n0') +  '/' 
	
	# Handle output messages
	if msg:
		if msg == 'msg1':
			msg = 'Account created successfully!';
		if msg == 'msg2': 
			msg = 'Account updated successfully!';
		if msg == 'msg3':
			msg = 'Account deleted successfully!'
	# Render the accounts template
	return render_template('admin/chats.html', accounts=accounts, msg=msg, selected='chats', selected_child='view',page=page, search=search, order=order, order_by=order_by, results_per_page=results_per_page, accounts_total=accounts_total['total'], math=math, url=url, time_elapsed_string=time_elapsed_string)


# http://localhost:5000/admin/accounts - view all accounts
@app.route('/admin/accounts/<string:msg>/<string:search>/<string:status>/<string:activation>/<string:role>/<string:order>/<string:order_by>/<int:page>', methods=['GET', 'POST'])
@app.route('/admin/accounts/', methods=['GET', 'POST'], defaults={'msg': '', 'search' : '', 'status': '', 'activation': '', 'role': '', 'order': 'DESC', 'order_by': '', 'page': 1})
def admin_accounts(msg, search, status, activation, role, order, order_by, page):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Params validation
	msg = '' if msg == 'n0' else msg
	search = '' if search == 'n0' else search
	status = '' if status == 'n0' else status
	activation = '' if activation == 'n0' else activation
	role = '' if role == 'n0' else role
	order = 'DESC' if order == 'DESC' else 'ASC'
	order_by_whitelist = ['id','username','plan_id','email','activation_code','role','registered','last_seen']
	order_by = order_by if order_by in order_by_whitelist else 'id'
	results_per_page = 20
	param1 = (page - 1) * results_per_page
	param2 = results_per_page
	param3 = '%' + search + '%'
	# SQL where clause
	where = '';
	where += 'WHERE (username LIKE %s OR email LIKE %s) ' if search else ''
	# Add filters
	if status == 'active':
		where += 'AND last_seen > date_sub(now(), interval 1 month) ' if where else 'WHERE last_seen > date_sub(now(), interval 1 month) '
	if status == 'inactive':
		where += 'AND last_seen < date_sub(now(), interval 1 month) ' if where else 'WHERE last_seen < date_sub(now(), interval 1 month) '
	if activation == 'pending':
		where += 'AND activation_code != "activated" ' if where else 'WHERE activation_code != "activated" '
	if role:
		where += 'AND role = %s ' if where else 'WHERE role = %s '
	# Params array and append specified params
	params = []
	if search:
		params.append(param3)
		params.append(param3)
	if role:
		params.append(role)
	
	# Fetch the total number of accounts
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT COUNT(*) AS total FROM accounts ' + where, params)
	accounts_total = cursor.fetchone()
	# Append params to array
	params.append(param1)
	params.append(param2)
	# Retrieve all accounts from the database
	cursor.execute('SELECT * FROM accounts ' + where + ' ORDER BY ' + order_by + ' ' + order + ' LIMIT %s,%s', params)
	accounts = cursor.fetchall()
	# Determine the URL
	url = url_for('admin_accounts') + '/n0/' + (search if search else 'n0') + '/' + (status if status else 'n0') + '/' + (activation if activation else 'n0') + '/' + (role if role else 'n0')
	# Handle output messages
	if msg:
		if msg == 'msg1':
			msg = 'Account created successfully!';
		if msg == 'msg2': 
			msg = 'Account updated successfully!';
		if msg == 'msg3':
			msg = 'Account deleted successfully!'
	# Render the accounts template
	return render_template('admin/accounts.html', accounts=accounts, selected='accounts', selected_child='view', msg=msg, page=page, search=search, status=status, activation=activation, role=role, order=order, order_by=order_by, results_per_page=results_per_page, accounts_total=accounts_total['total'], math=math, url=url, time_elapsed_string=time_elapsed_string)

# http://localhost:5000/admin/roles - view account roles
@app.route('/admin/roles/', methods=['GET', 'POST'])
def admin_roles():
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Set the connection cursor
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Select and group roles from the accounts table
	cursor.execute('SELECT role, COUNT(*) as total FROM accounts GROUP BY role')
	roles = cursor.fetchall()
	new_roles = {}
	# Update the structure
	for role in roles:
		new_roles[role['role']] = role['total']
	for role in roles_list:
		if not new_roles[role]:
			new_roles[role] = 0
	# Get the total number of active roles
	cursor.execute('SELECT role, COUNT(*) as total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month) GROUP BY role')
	roles_active = cursor.fetchall()
	new_roles_active = {}
	for role in roles_active:
		new_roles_active[role['role']] = role['total']
	# Get the total number of inactive roles
	cursor.execute('SELECT role, COUNT(*) as total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month) GROUP BY role')
	roles_inactive = cursor.fetchall()
	new_roles_inactive = {}
	for role in roles_inactive:
		new_roles_inactive[role['role']] = role['total']
	#Plans
	cursor.execute('SELECT plan_id, COUNT(*) as total FROM accounts GROUP BY plan_id')
	plans = cursor.fetchall()
	plan_names = {
        1: 'Explorer',
        2: 'Adventurer',
        3: 'Conqueror',
        4: 'The sky is the limit',
		5: 'AppSumo Tier 1',
		6: 'AppSumo Tier 2',
		7: 'AppSumo Tier 3'
    }
	# Render he roles template
	return render_template('admin/roles.html', plan_names=plan_names, plans=plans, selected='roles', selected_child='', enumerate=enumerate, roles=new_roles, roles_active=new_roles_active, roles_inactive=new_roles_inactive)

def get_logs():
	with open('gunicorn.log', 'r') as f:
		file_content = f.readlines()
	file_content.reverse()
	return ''.join(file_content)

@app.route('/admin/reboot/', methods=['GET', 'POST'])
def reboot():
	if not admin_loggedin():
		return redirect(url_for('login'))
	# execude deploy.sh
	os.system('sh deploy.sh')
	return redirect(url_for('admin'))


# FUNCTION TO ARCHIVE LOG FILE AND CREATE A NEW ONE
@app.route('/admin/archive_log_file/', methods=['GET', 'POST'])
def archive_log_file():
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Get the current date
	now = datetime.datetime.now()
	# Get the current log file name
	log_file_name = 'gunicorn.log'
	# Get the current log file path
	log_file_path = os.path.join(os.getcwd(), log_file_name)
	# Get the new log file name
	new_log_file_name = log_file_name + '-' + now.strftime('%Y-%m-%d--%H-%M-%S') + '.log'
	# Get the new log file path
	new_log_file_path = os.path.join(os.getcwd(), new_log_file_name)
	# Rename the current log file to the new log file
	os.rename(log_file_path, new_log_file_path)
	# Create a new log file
	open(log_file_name, 'a').close()
	logs = get_logs()
	msg = 'Log file archived successfully!'
	return redirect(url_for('admin_logs', msg=msg, logs=logs, selected='logs', selected_child=''))

# http://localhost:5000/admin/logs - manage logs
@app.route('/admin/logs/<string:msg>', methods=['GET', 'POST'])
@app.route('/admin/logs/', methods=['GET', 'POST'], defaults={'msg': ''})
def admin_logs(msg):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Get logs
	logs = get_logs()
	

	# Render the settings template
	return render_template('admin/logs.html', selected='logs', selected_child='', msg=msg, logs=logs)


# http://localhost:5000/admin/settings - manage settings
@app.route('/admin/settings/<string:msg>', methods=['GET', 'POST'])
@app.route('/admin/settings/', methods=['GET', 'POST'], defaults={'msg': ''})
def admin_settings(msg):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Get settings
	settings = get_settings()
	# Set the connection cursor
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# If user submitted the form
	if request.method == 'POST' and request.form:
		# Retrieve the form data
		data = request.form
		# Iterate the form data
		for key, value in data.items():
			# Check if checkbox is checked
			if 'true' in request.form.getlist(key):
				value = 'true'
			# Convert boolean values to lowercase
			value = value.lower() if value.lower() in ['true', 'false'] else value
			# Update setting
			cursor.execute('UPDATE settings SET setting_value = %s WHERE setting_key = %s', (value,key,))
			mysql.connection.commit()
		# Redirect and output message
		return redirect(url_for('admin_settings', msg='msg1'))
	# Handle output messages
	if msg and msg == 'msg1':
		msg = 'Settings updated successfully!';
	else:
		msg = ''
	# Render the settings template
	return render_template('admin/settings.html', selected='settings', selected_child='', msg=msg, settings=settings, settings_format_tabs=settings_format_tabs, settings_format_form=settings_format_form)

# http://localhost:5000/admin/about - view the about page
@app.route('/admin/about/', methods=['GET', 'POST'])
def admin_about():
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Render the about template
	return render_template('admin/about.html', selected='about', selected_child='')

# http://localhost:5000/admin/accounts/delete/<id> - delete account
@app.route('/admin/accounts/delete/<int:id>', methods=['GET', 'POST'])
@app.route('/admin/accounts/delete/', methods=['GET', 'POST'], defaults={'id': None})
def admin_delete_account(id):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Set the database connection cursor
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Delete account from database by the id get request param
	cursor.execute('DELETE FROM accounts WHERE id = %s', (id,))
	mysql.connection.commit()
	# Redirect to accounts page and output message
	return redirect(url_for('admin_accounts', msg='msg3', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))

# http://localhost:5000/admin/chats/delete/<id> - delete chatbot
@app.route('/admin/chats/delete/<int:id>', methods=['GET', 'POST'])
@app.route('/admin/chats/delete/', methods=['GET', 'POST'], defaults={'id': None})
def admin_delete_chat(id):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Set the database connection cursor
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Delete account from database by the id get request param
	cursor.execute('DELETE FROM user_docs WHERE id = %s', (id,))
	mysql.connection.commit()
	# Redirect to accounts page and output message
	return redirect(url_for('admin_chats', msg='msg3', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))


# http://localhost:5000/admin/account/<optional:id> - create or edit account
@app.route('/admin/account/<int:id>', methods=['GET', 'POST'])
@app.route('/admin/account/', methods=['GET', 'POST'], defaults={'id': None})
def admin_account(id):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Default page (Create/Edit)
	page = 'Create'
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	# Default input account values
	account = {
		'username': '',
		'password': '',
		'email': '',
		'activation_code': '',
		'rememberme': '',
		'role': 'Member',
		'registered': str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
		'last_seen': str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
	}
	roles = ['Member', 'Admin']
	plans = [1,2,3,4,5,6,7]
	plan_names = {
        1: 'Explorer',
        2: 'Adventurer',
        3: 'Conqueror',
        4: 'The sky is the limit',
		5: 'AppSumo Tier 1',
		6: 'AppSumo Tier 2',
		7: 'AppSumo Tier 3'
    }
	# GET request ID exists, edit account
	if id:
		# Edit an existing account
		page = 'Edit'
		# Retrieve account by ID with the GET request ID
		cursor.execute('SELECT * FROM accounts WHERE id = %s', (id,))
		account = cursor.fetchone()
		# If user submitted the form
		if request.method == 'POST' and 'submit' in request.form:
			# update account
			password = account['password']
			# If password exists in POST request
			if request.form['password']:
				hash = request.form['password'] + app.secret_key
				hash = hashlib.sha1(hash.encode())
				password = hash.hexdigest();
			# Update account details
			cursor.execute('UPDATE accounts SET username = %s, password = %s, email = %s,plan_id=%s, activation_code = %s, rememberme = %s, role = %s, registered = %s, last_seen = %s WHERE id = %s', (request.form['username'],password,request.form['email'],request.form['plan_id'],request.form['activation_code'],request.form['rememberme'],request.form['role'],request.form['registered'],request.form['last_seen'],id,))
			mysql.connection.commit()
			# Redirect to admin accounts page
			return redirect(url_for('admin_accounts', msg='msg2', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))
		if request.method == 'POST' and 'delete' in request.form:
			# delete account
			return redirect(url_for('admin_delete_account', id=id))
	if request.method == 'POST' and request.form['submit']:
		# Create new account, hash password
		hash = request.form['password'] + app.secret_key
		hash = hashlib.sha1(hash.encode())
		password = hash.hexdigest();
		# Insert account into database
		cursor.execute('INSERT INTO accounts (username,password,email,activation_code,rememberme,role,registered,last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (request.form['username'],password,request.form['email'],request.form['activation_code'],request.form['rememberme'],request.form['role'],request.form['registered'],request.form['last_seen'],))
		mysql.connection.commit()
		# Redirect to the admin accounts page and output message
		return redirect(url_for('admin_accounts', msg='msg1', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))
	# Render the admin account template
	return render_template('admin/account.html', account=account, selected='accounts', selected_child='manage', page=page, plan_names=plan_names, plans=plans,roles=roles, datetime=datetime.datetime, str=str)

# http://localhost:5000/admin/emailtemplate - admin email templates page, manage email templates
@app.route('/admin/emailtemplate/<string:msg>', methods=['GET', 'POST'])
@app.route('/admin/emailtemplate/', methods=['GET', 'POST'], defaults={'msg': ''})
def admin_emailtemplate(msg):
	# Check if admin is logged-in
	if not admin_loggedin():
		return redirect(url_for('login'))
	# Get the template directory path
	template_dir = os.path.join(os.path.dirname(__file__), 'templates')
	# Update the template file on save
	if request.method == 'POST':
		# Update activation template
		activation_email_template = request.form['activation_email_template'].replace('\r', '')
		open(template_dir + '/activation-email-template.html', mode='w', encoding='utf-8').write(activation_email_template)
		# Update twofactor template
		twofactor_email_template = request.form['twofactor_email_template'].replace('\r', '')
		open(template_dir + '/twofactor-email-template.html', mode='w', encoding='utf-8').write(twofactor_email_template)
		# Redirect and output success message
		return redirect(url_for('admin_emailtemplate', msg='msg1'))
	# Read the activation email template
	activation_email_template = open(template_dir + '/activation-email-template.html', mode='r', encoding='utf-8').read()
	# Read the twofactor email template
	twofactor_email_template = open(template_dir + '/twofactor-email-template.html', mode='r', encoding='utf-8').read()
	# Handle output messages
	if msg and msg == 'msg1':
		msg = 'Email templates updated successfully!';
	else:
		msg = ''
	# Render template
	return render_template('admin/emailtemplates.html', selected='emailtemplate', selected_child='', msg=msg, activation_email_template=activation_email_template, twofactor_email_template=twofactor_email_template)

# Admin logged-in check function
def admin_loggedin():
	if loggedin() and session['role'] == 'Admin':
		# admin logged-in
		return True
	# admin not logged-in return false
	return False

# format settings key
def settings_format_key(key):
	key = key.lower().replace('_', ' ').replace('url', 'URL').replace('db ', 'Database ').replace(' pass', ' Password').replace(' user', ' Username')
	return key.title()

# Format settings variables in HTML format
def settings_format_var_html(key, value):
	html = ''
	type = 'text'
	type = 'password' if 'pass' in key else type
	type = 'checkbox' if value.lower() in ['true', 'false'] else type
	checked = ' checked' if value.lower() == 'true' else ''
	html += '<label for="' + key + '">' + settings_format_key(key) + '</label>'
	if (type == 'checkbox'):
		html += '<input type="hidden" name="' + key + '" value="false">'
	html += '<input type="' + type + '" name="' + key + '" id="' + key + '" value="' + value + '" placeholder="' + settings_format_key(key) + '"' + checked + '>'
	return html

# Format settings tabs
def settings_format_tabs(tabs):
	html = ''
	html += '<div class="tabs">'
	html += '<a href="#" class="active">General</a>'
	for tab in tabs:
		html += '<a href="#">' + tab + '</a>'
	html += '</div>'
	return html

# Format settings form
def settings_format_form(settings):
	html = ''
	html += '<div class="tab-content active">'
	category = ''
	for setting in settings:
		if category != '' and category != settings[setting]['category']:
			html += '</div><div class="tab-content">'
		category = settings[setting]['category']
		html += settings_format_var_html(settings[setting]['key'], settings[setting]['value'])
	html += '</div>'
	return html

# Get settings from database
def get_settings():
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM settings ORDER BY id')
	settings = cursor.fetchall()
	settings2 = {}
	for setting in settings:
		settings2[setting['setting_key']] = { 'key': setting['setting_key'], 'value': setting['setting_value'], 'category': setting['category'] }
	return settings2

# Format datetime
def time_elapsed_string(dt):
	d = datetime.datetime.strptime(str(dt), '%Y-%m-%d %H:%M:%S')
	dd = datetime.datetime.now()
	d = d.timestamp() - dd.timestamp()
	d = datetime.timedelta(seconds=d)
	timeDelta = abs(d)
	if timeDelta.days > 0:
		if timeDelta.days == 1:
			return '1 day ago'
		else:
			return '%s days ago' % timeDelta.days
	elif round(timeDelta.seconds / 3600) > 0:
		if round(timeDelta.seconds / 3600) == 1:
			return '1 hour ago'
		else:
			return '%s hours ago' % round(timeDelta.seconds / 3600)
	elif round(timeDelta.seconds / 60) < 2:
		return '1 minute ago'
	else:
		return '%s minutes ago' % round(timeDelta.seconds / 60) 

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8000)
