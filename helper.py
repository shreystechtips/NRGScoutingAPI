import os
import base64
from dotenv import load_dotenv
from flask import render_template
load_dotenv()


def generate_google_service(fileName):
    open(fileName, "w+").write(base64ToString(os.getenv("FIREBASE_SERVICE_CODE")))
    return fileName


def base64ToString(b):
    return base64.b64decode(bytes(b, "utf-8").decode('unicode_escape')).decode('utf-8')


def stringToBase64(s):
    return base64.b64encode(s.encode('utf-8'))


def render_doc_template(route):
    return render_template('endpoints.html', name=route, body=open('./templates/endpoints/' + route[1:].replace('/', '.')+'.txt').read())
