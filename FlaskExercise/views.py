from flask import render_template, redirect, request, session, url_for
from msal import ConfidentialClientApplication
from flask_login import current_user, login_user, logout_user, login_required
import msal
import uuid
from config import Config
from FlaskExercise import app
from FlaskExercise.models import User


@app.route('/')
@app.route('/home')
@login_required
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    session['state'] = str(uuid.uuid4())
    # Note: Below will return None as an auth_url until you implement the function
    cache = _load_cache()
    msal_app = _build_msal_app(cache=cache)
    auth_url = _build_auth_url(msal_app=msal_app, state=session['state'])
    return render_template('login.html', title='Sign In', auth_url=auth_url)


@app.route('/logout')
def logout():
    logout_user() # Log out of Flask session
    if session.get('user'): # Used MS Login
        # Wipe out user and its token cache from session
        session.clear()
        # TODO: Also logout from your tenant's web session
        #   And make sure to redirect from there back to the login page
        return redirect(
            Config.AUTHORITY + "/oauth2/v2.0/logout" +
            "?post_logout_redirect_uri=" + url_for("login", _external=True)
        )

    return redirect(url_for('login'))


@app.route(Config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    if request.args.get('state') != session.get('state'):
        return redirect(url_for('home'))  # Failed, go back home
    if 'error' in request.args:  # Authentication/Authorization failure
        return render_template('auth_error.html', result=request.args)
    if request.args.get('code'):
        cache = _load_cache()
        # TODO: Acquire a token by authorization code from an MSAL app
        #  And replace the error dictionary
        msal_app = _build_msal_app(cache)
        code = request.args.get("code")
        result = msal_app.acquire_token_by_authorization_code(
            code,
            scopes=Config.SCOPE
        )
        if 'error' in result:
            return render_template('auth_error.html', result=result)
        session['user'] = result.get('id_token_claims')
        # Note: In a real app, use the appropriate user's DB ID below,
        #   but here, we'll just log in with a fake user zero
        #   This is so flask login functionality works appropriately.
        user = User(0)
        login_user(user)
        _save_cache(cache)

    return redirect(url_for('home'))


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get('token_cache'):
        cache.deserialize(session['token_cache'])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session['token_cache'] = cache.serialize()


def _build_msal_app(cache=None):
    # TODO: Create and return a Confidential Client Application from msal
    return ConfidentialClientApplication(
        client_id=Config.CLIENT_ID,
        authority=Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET,
        token_cache=cache
    )


def _build_auth_url(msal_app: ConfidentialClientApplication,  state=None):
    # TODO: Get the authorization request URL from a built msal app, and return it
    return msal_app.get_authorization_request_url(
        Config.SCOPE,
        redirect_uri="https://test-entra-id-app.azurewebsites.net"+ Config.REDIRECT_PATH,
        state=state
    )