from flask import session
import json

import os

def get_user_files(json_record_path):
    user_id = session.get('user_id')
    if not user_id:
        return []
    
    files_json = load_json(json_record_path)
    files = files_json["files"]

    user_files = []
    for file in files:

        print("File: ", file)
        if file["user_id"] == user_id:
            user_files.append(file)

    return user_files



def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_json(json_path):
    """Helper function to load JSON data from the file."""
    try:
        with open(json_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {'users': []}


def save_json(data, json_path):
    """Helper function to save data back to the JSON file."""
    with open(json_path, 'w') as file:
        json.dump(data, file, indent=4)