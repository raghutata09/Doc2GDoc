import os
import flask
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.oauth2 import service_account
import json
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Flask app to handle OAuth
app = flask.Flask(__name__)
app.secret_key = 'your_secret_key'
CLIENT_SECRETS_FILE = 'D:\Wokelo\secure\client_secret_693155361024-b0nsltsau5hpf4ok14jqdn7qk801gifn.apps.googleusercontent.com.json'

SCOPES = ['https://www.googleapis.com/auth/drive.file']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'

# Function to start the OAuth 2.0 flow and get user credentials
@app.route('/authorize')
def authorize():
    # Create a flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    # Store the state in the session to validate it in the callback.
    flask.session['state'] = state

    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback to prevent CSRF.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    # Save credentials to a local file
    save_credentials_to_file(credentials, "D:\Wokelo\credentials1.json")

    return 'Authorization complete! You can now use the /convert endpoint.'

def save_credentials_to_file(credentials, file_path):
    # Convert credentials to a dictionary
    credentials_dict = credentials_to_dict(credentials)
    
    # Save the dictionary to a JSON file
    with open(file_path, 'w') as file:
        json.dump(credentials_dict, file)

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# Function to get authenticated credentials for the user
def get_user_credentials():
    # Check if credentials are stored in the session.
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    # Check if the credentials are expired and refresh them if necessary.
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(google.auth.transport.requests.Request())

    # Update the session with new credentials.
    flask.session['credentials'] = credentials_to_dict(credentials)

    return credentials

@app.route('/convert', methods=['GET'])
def convert_docx_to_gdoc():
    # Extract the file path from the query parameters
    file_path = flask.request.args.get('file_path')
    
    if not file_path or not os.path.exists(file_path):
        return "The provided file path is invalid.", 400

    # Obtain user credentials
    credentials = get_user_credentials()

    # Initialize the Google Drive API client
    drive_service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)
    
    # Upload and convert the .docx file to a Google Doc
    file_metadata = {
        'name': os.path.basename(file_path),
        'mimeType': 'application/vnd.google-apps.document'  # Convert to Google Doc
    }           
    print("file_path = "+file_path)
    media = MediaFileUpload(file_path, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    
    try:
        file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, webViewLink').execute()

        return {
            "file_id": file.get('id'),
            "file_name": file.get('name'),
            "webViewLink": file.get('webViewLink')
        }
    except Exception as e:
        return f"An error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run('localhost', 5000, debug=True)