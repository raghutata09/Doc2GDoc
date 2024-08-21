from flask import Flask, request, redirect, url_for, jsonify
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from oauth2client.service_account import ServiceAccountCredentials
import os

app = Flask(__name__)

# Authentication
gauth = GoogleAuth()

# Load client secrets
gauth.LoadClientConfigFile("D:\Wokelo\secure\client_secret_693155361024-b0nsltsau5hpf4ok14jqdn7qk801gifn.apps.googleusercontent.com.json")
gauth.LocalWebserverAuth()  # Creates local webserver and auto handles authentication.

drive = GoogleDrive(gauth)

@app.route('/upload_docx', methods=['POST'])
def upload_docx():
    # Check if the POST request has the file part
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and file.filename.endswith('.docx'):
        # Save the file temporarily
        file_path = os.path.join(os.getcwd(), file.filename)
        file.save(file_path)

        # Upload the .docx file to Google Drive as a Google Doc
        gfile = drive.CreateFile({'title': file.filename, 'mimeType': 'application/vnd.google-apps.document'})
        gfile.SetContentFile(file_path)
        gfile.Upload()

        # Delete the file locally after upload
        os.remove(file_path)

        return jsonify({
            "success": True,
            "file_id": gfile['id'],
            "file_link": f"https://docs.google.com/document/d/{gfile['id']}/edit"
        })

    return jsonify({"error": "Invalid file type, only .docx is allowed"}), 400


if __name__ == '__main__':
    app.run(debug=True)
