import os
import secrets
import logging
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import Flask, redirect, url_for, render_template, flash, session, \
    current_app, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    current_user
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Console output
        logging.FileHandler('oauth_debug.log')  # File output
    ]
)
logger = logging.getLogger(__name__)

app.config['OAUTH2_PROVIDERS'] = {
    # Google OAuth 2.0 documentation:
    # https://developers.google.com/identity/protocols/oauth2/web-server#httprest
    'google': {
        'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
        'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
        'token_url': 'https://accounts.google.com/o/oauth2/token',
        'userinfo': {
            'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
            'email': lambda json: json['email'],
        },
        'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
    },

    # GitHub OAuth 2.0 documentation:
    # https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
    'github': {
        'client_id': os.environ.get('GITHUB_CLIENT_ID'),
        'client_secret': os.environ.get('GITHUB_CLIENT_SECRET'),
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'userinfo': {
            'url': 'https://api.github.com/user/emails',
            'email': lambda json: json[0]['email'],
        },
        'scopes': ['user:email'],
    },
}

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'index'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=True)


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


@app.route('/')
def index():
    logger.info("=== INDEX PAGE ACCESSED ===")
    logger.info(f"Current user authenticated: {not current_user.is_anonymous}")
    if not current_user.is_anonymous:
        logger.info(f"Current user: {current_user.email}")
    return render_template('index.html')


@app.route('/logout')
def logout():
    logger.info("=== LOGOUT INITIATED ===")
    logger.info(f"Logging out user: {current_user.email if not current_user.is_anonymous else 'Anonymous'}")
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/authorize/<provider>')
def oauth2_authorize(provider):
    logger.info(f"=== OAUTH2 AUTHORIZATION STARTED ===")
    logger.info(f"Provider: {provider}")
    logger.info(f"Current user anonymous: {current_user.is_anonymous}")
    
    if not current_user.is_anonymous:
        logger.info("User already authenticated, redirecting to index")
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        logger.error(f"Provider '{provider}' not found in configuration")
        abort(404)

    logger.info(f"Provider configuration found for: {provider}")
    logger.info(f"Client ID: {provider_data['client_id'][:10]}..." if provider_data['client_id'] else "Client ID: None")
    logger.info(f"Authorize URL: {provider_data['authorize_url']}")
    logger.info(f"Scopes: {provider_data['scopes']}")

    # generate a random string for the state parameter
    session['oauth2_state'] = secrets.token_urlsafe(16)
    logger.info(f"Generated OAuth2 state: {session['oauth2_state']}")

    # create a query string with all the OAuth2 parameters
    redirect_uri = url_for('oauth2_callback', provider=provider, _external=True)
    logger.info(f"Redirect URI: {redirect_uri}")
    
    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })
    
    authorization_url = provider_data['authorize_url'] + '?' + qs
    logger.info(f"Full authorization URL: {authorization_url}")

    # redirect the user to the OAuth2 provider authorization URL
    logger.info("Redirecting user to OAuth2 provider...")
    return redirect(authorization_url)


@app.route('/callback/<provider>')
def oauth2_callback(provider):
    logger.info(f"=== OAUTH2 CALLBACK RECEIVED ===")
    logger.info(f"Provider: {provider}")
    logger.info(f"Request args: {dict(request.args)}")
    
    if not current_user.is_anonymous:
        logger.info("User already authenticated, redirecting to index")
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        logger.error(f"Provider '{provider}' not found in configuration")
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if 'error' in request.args:
        logger.error("=== OAUTH2 ERROR RECEIVED ===")
        for k, v in request.args.items():
            if k.startswith('error'):
                logger.error(f'{k}: {v}')
                flash(f'{k}: {v}')
        return redirect(url_for('index'))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    received_state = request.args.get('state')
    session_state = session.get('oauth2_state')
    logger.info(f"State validation - Received: {received_state}, Session: {session_state}")
    
    if received_state != session_state:
        logger.error("State parameter mismatch - possible CSRF attack")
        abort(401)

    # make sure that the authorization code is present
    auth_code = request.args.get('code')
    if not auth_code:
        logger.error("Authorization code not present in callback")
        abort(401)
    
    logger.info(f"Authorization code received: {auth_code[:10]}...")

    # exchange the authorization code for an access token
    logger.info("=== EXCHANGING CODE FOR TOKEN ===")
    token_data = {
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': auth_code,
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('oauth2_callback', provider=provider, _external=True),
    }
    
    logger.info(f"Token request URL: {provider_data['token_url']}")
    logger.info(f"Token request data keys: {list(token_data.keys())}")
    
    try:
        response = requests.post(provider_data['token_url'], data=token_data, 
                               headers={'Accept': 'application/json'}, timeout=30)
        logger.info(f"Token response status: {response.status_code}")
        logger.info(f"Token response headers: {dict(response.headers)}")
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed with status {response.status_code}")
            logger.error(f"Response body: {response.text}")
            abort(401)
            
        token_json = response.json()
        oauth2_token = token_json.get('access_token')
        
        if not oauth2_token:
            logger.error("Access token not found in response")
            logger.error(f"Full token response: {token_json}")
            abort(401)
            
        logger.info(f"Access token received: {oauth2_token[:10]}...")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Token request failed with exception: {str(e)}")
        abort(401)

    # use the access token to get the user's email address
    logger.info("=== FETCHING USER INFO ===")
    userinfo_url = provider_data['userinfo']['url']
    logger.info(f"Userinfo URL: {userinfo_url}")
    
    try:
        response = requests.get(userinfo_url, headers={
            'Authorization': 'Bearer ' + oauth2_token,
            'Accept': 'application/json',
        }, timeout=30)
        
        logger.info(f"Userinfo response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Userinfo request failed with status {response.status_code}")
            logger.error(f"Response body: {response.text}")
            abort(401)
            
        userinfo_json = response.json()
        logger.info(f"Userinfo received for user: {userinfo_json.get('email', 'unknown')}")
        
        email = provider_data['userinfo']['email'](userinfo_json)
        logger.info(f"Extracted email: {email}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Userinfo request failed with exception: {str(e)}")
        abort(401)
    except Exception as e:
        logger.error(f"Email extraction failed: {str(e)}")
        abort(401)

    # find or create the user in the database
    logger.info("=== USER DATABASE OPERATIONS ===")
    user = db.session.scalar(db.select(User).where(User.email == email))
    
    if user is None:
        logger.info(f"Creating new user with email: {email}")
        user = User(email=email, username=email.split('@')[0])
        db.session.add(user)
        db.session.commit()
        logger.info(f"New user created with ID: {user.id}")
    else:
        logger.info(f"Existing user found with ID: {user.id}")

    # log the user in
    logger.info("=== LOGGING USER IN ===")
    login_user(user)
    logger.info(f"User {user.email} successfully logged in")
    
    return redirect(url_for('index'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    logger.info("=== STARTING FLASK APPLICATION ===")
    logger.info("Debug mode: ON")
    app.run(debug=True)