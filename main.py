from flask import request, abort, jsonify, json, render_template, redirect, url_for
import io
import flask
from flask_cors import CORS
import requests
from datetime import datetime, timedelta
import os
# import re
# import jwt
from passlib.context import CryptContext
from binascii import hexlify
from flask_bcrypt import Bcrypt
import psycopg2
from dotenv import load_dotenv
import pyrebase
import helper

load_dotenv()

config = {
    "apiKey": os.getenv("FIREBASE_KEY"),
    "authDomain": str(os.getenv("FIREBASE_PROJ_NAME")) + ".firebaseapp.com",
    "storageBucket": str(os.getenv("FIREBASE_PROJ_NAME")) + ".appspot.com",
    "databaseURL": "https://" + str(os.getenv("FIREBASE_PROJ_NAME")) + ".firebaseio.com",
    "serviceAccount": helper.generate_google_service("service.json")
}

firebase = pyrebase.initialize_app(config)
storage = firebase.storage()

try:
    # INIT FIREBASE
    os.remove("service.json")
except:
    None


app = flask.Flask(__name__)
CORS(app)
app.Debug = False
bcrypt = Bcrypt(app)
SECRET = os.getenv("SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 3

cache_folder = os.path.join('cache/')
request_values = json.loads(open("request_values.json", "rb").read())
BASE_API_URL = "https://www.thebluealliance.com/api/v3"
API_KEY = os.getenv("TBA_KEY")


con = psycopg2.connect(os.getenv("DATABASE_URL"), sslmode='require')


cur = con.cursor()
postgres_insert_query = """ INSERT INTO users (email, password, team, auth_key) VALUES (%s,%s,%s,%s)"""
postgres_exists_query = """ select * from users where {0} = {2}{1}{2} """


def check_key():
    cur.execute(postgres_exists_query.format(
        'auth_key', 'b\'\'' + request.headers.get('API-Key') + '\'\'', '\''))
    return not cur.fetchone() == None


def check_request():
    endpt = request.url_rule.rule
    request_json = request.json
    for key in request_values[endpt]:
        if not key in request_json:
            abort(400, "Not all parameters are submitted")


def auth_headers():
    return {'X-TBA-Auth-Key': API_KEY}


def simplify_data(data):
    temp = {'team_number': data['team_number'], "nickname": data['nickname']}
    return temp


def update_cache(path, url):
    storage.child('/')
    try:
        if not os.path.exists(path):
            storage.child(path).download(path)
        yearfile = open(path, 'r')
        try:
            date_file = datetime.strptime(yearfile.readline().strip(), '%c')
            TBA_file = datetime.strptime(
                helper.file_last_updated(url), '%a, %d %b %Y %X %Z')
            if date_file > TBA_file:
                return json.loads(yearfile.readline()), False
        except:
            return [], True
    except:
        return [], True
    return [], True

# Overwrites file with current time and stringifys the json


def write_to_file(data, file_path, filename):
    print(file_path)
    if not os.path.exists(file_path):
        os.makedirs(file_path)
    path = os.path.join(file_path, filename)
    print(path)
    f = open(path, 'w+')
    f.write(str(datetime.utcnow().strftime('%c'))+'\n'+json.dumps(data))
    storage.child('/')
    storage.child(path).put(path)
    # os.remove(path)


def get_teams(year, CACHE_CONST):
    filename = str(year) + '.txt'
    txt, update = update_cache(os.path.join(
        cache_folder, CACHE_CONST, filename), os.path.join(BASE_API_URL, "teams", str(year),
                                                           str(0), 'simple'))

    if not update:
        return txt

    all_data = []
    pg = 0
    while True:
        r = requests.get(url=os.path.join(BASE_API_URL, "teams", str(year),
                                          str(pg), 'simple'), headers=auth_headers())
        r = r.json()
        if len(r) == 0:
            write_to_file(all_data, os.path.join(
                cache_folder, CACHE_CONST), filename)
            return all_data
        for data in r:
            all_data.append(simplify_data(data))
        pg += 1


@app.route('/', methods=['GET'])
def main():
    message = ''
    return render_template('index.html', message=message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        data = request.values
        users_doc = {
            "email": data.get("email"),
            "password": bcrypt.generate_password_hash(data.get("password")).decode('utf-8'),
            "team": data.get("team")
        }

        cur.execute(postgres_exists_query.format(
            'email', users_doc["email"], '\''))
        if cur.fetchone() == None:
            to_insert = (users_doc["email"], str(
                users_doc["password"]), int(users_doc['team']), str(hexlify(os.urandom(16))))
            cur.execute(postgres_insert_query, to_insert)
            con.commit()
            return redirect(url_for('.login'))
        else:
            message = "User email already exists, please try signing in with password"
    return render_template('sign_up.html', message=message)


@app.route('/login', methods=['POST', 'GET'])
def login():
    message = ""
    if request.method == 'POST':
        data = request.values
        users_doc = {
            "email": data.get("email"),
            "password": data.get("password"),
        }
        cur.execute(postgres_exists_query.format(
            'email', users_doc["email"], '\''))
        temp = cur.fetchone()
        if temp and bcrypt.check_password_hash(temp[1], users_doc['password']):
            message = "Your API Key is: " + \
                str(temp[3])[2:len(temp[3])-1] + \
                " DO NOT SHARE IT with anyone!"
        else:
            message = "Incorrect username or password"
    return render_template('login.html', message=message)

# PARAMS: int(year)
@app.route('/teams', methods=['POST', 'GET'])
def teams():
    if request.method == 'GET':
        return helper.render_doc_template(request.url_rule.rule)
    check_request()
    CACHE_CONST = 'teams'
    json_in = request.json
    if not check_key():
        return jsonify(["Not Allowed, please use a valid API Key"]), 403
    return jsonify(get_teams(str(json_in['year']), CACHE_CONST)), 200

# PARAMS: str(event_key)
@app.route('/event/teams', methods=['POST', 'GET'])
def event_teams():
    if request.method == 'GET':
        return helper.render_doc_template(request.url_rule.rule)
    check_request()
    CACHE_CONST = 'event'
    json_in = request.json
    REQUEST_URL = os.path.join(BASE_API_URL, 'event',
                               json_in['event_key'], 'teams')
    if not check_key():
        return jsonify(["Not Allowed, please use a valid API Key"]), 403

    filename = json_in['event_key'] + '.txt'
    txt,  update = update_cache(os.path.join(
        cache_folder, CACHE_CONST, filename), REQUEST_URL)
    if not update:
        return jsonify(txt), 200

    r = requests.get(url=REQUEST_URL, headers=auth_headers())
    if r.status_code == 404:
        abort(404)

    all_data = []
    r = r.json()
    for item in r:
        all_data.append(simplify_data(item))
    write_to_file(all_data, os.path.join(cache_folder, CACHE_CONST), filename)

    return jsonify(all_data), 200

# Remove the 'frc' from the start of team keys from data and normalizes it into integers


def process_team_keys(keys):
    removal_key = 'frc'
    teams = []
    for key in keys:
        if removal_key in key:
            teams.append(int(key[key.index(removal_key)+len(removal_key):]))
        elif key.isdigit():
            teams.append(key)
        else:
            abort(404)

    return teams


# Takes parameters: str(event_key), str(comp_level), bool(uses_sets)
@app.route('/event/matches', methods=['POST', 'GET'])
def get_matches():
    if request.method == 'GET':
        return helper.render_doc_template(request.url_rule.rule)
    check_request()
    CACHE_CONST = 'event'
    json_in = request.json
    REQUEST_URL = os.path.join(BASE_API_URL, 'event', json_in['event_key'],
                               'matches', 'simple')

    if not check_key():
        return abort(403)

    filename = json_in['event_key'] + '.matches.' + json_in[
        'comp_level'] + '.' + str(json_in['uses_sets']) + '.txt'

    # REGEX_PATTERN = re.compile("(^\w+_" + json_in['comp_level'] + "\d+)$")

    txt, update = update_cache(
        os.path.join(cache_folder, CACHE_CONST, filename), REQUEST_URL)

    if not update:
        return jsonify(txt), 200

    r = requests.get(
        url=REQUEST_URL,
        headers=auth_headers())
    if r.status_code == 404:
        abort(404)

    all_data = {}
    r = r.json()
    for item in r:
        if item['comp_level'] == json_in['comp_level']:
            match_data = {}
            insert_val = ''
            if json_in['uses_sets']:
                insert_val = str(item['set_number']) + \
                    ',' + str(item['match_number'])
            else:
                if(json_in['comp_level'] == 'qf' or json_in['comp_level'] == 'sf'):
                    return jsonify(["cannot use numbers for qf or sf due to ties and rematches"]), 404
                insert_val = str(item['set_number']*item['match_number'])
            all_data[insert_val] = match_data
            alliances = item['alliances']
            match_data['blue'] = process_team_keys(
                alliances['blue']['team_keys'])
            match_data['red'] = process_team_keys(
                alliances['red']['team_keys'])
    write_to_file(all_data, os.path.join(cache_folder, CACHE_CONST), filename)
    return jsonify(all_data), 200


@app.route('/events', methods=['POST', 'GET'])
def events():
    if request.method == 'GET':
        return helper.render_doc_template(request.url_rule.rule)
    check_request()
    CACHE_CONST = 'event'
    json_in = request.json
    REQUEST_URL = os.path.join(BASE_API_URL, 'events',
                               str(json_in['year']), 'simple')

    if not check_key():
        return abort(403)

    filename = str(json_in['year']) + '.events.all.txt'
    txt, update = update_cache(
        (os.path.join(cache_folder, CACHE_CONST, filename)), REQUEST_URL)

    if not update:
        return jsonify(txt), 200

    r = requests.get(
        url=REQUEST_URL,
        headers=auth_headers())
    if r.status_code == 404:
        abort(404)

    all_data = []
    r = r.json()
    print(r)
    for item in r:
        all_data.append({'name': item['name'], 'key': item['key']})
    write_to_file(all_data, os.path.join(
        cache_folder, CACHE_CONST), filename)
    return jsonify(all_data), 200


def get_key_simple(keys):
    string = ''
    for key in keys:
        string += '.' + key + '.'


@app.route('/zebra', methods=['POST', 'GET'])
def zebra_img():
    if request.method == 'GET':
        return helper.render_doc_template(request.url_rule.rule)
    check_request()
    json_in = request.json
    REQUEST_URL = os.path.join(BASE_API_URL, 'match',
                               str(json_in['event_key']) + '_' + str(json_in['match_key']), 'zebra_motionworks')
    CACHE_CONST = 'event/' + json_in['event_key'] + '/'

    json_in['red_relative_keys'].sort()

    filename = json_in['match_key'] + \
        str(json_in['red_relative_keys']) + '.png'

    full_path = os.path.join(cache_folder, CACHE_CONST, filename)

    try:
        if not os.path.exists(full_path):
            storage.child(full_path).download(full_path)
    except:
        None

    if os.path.exists(full_path):
        return flask.send_file(filename_or_fp=full_path, mimetype='image/png')

    helper.plot_data(
        json_in['event_key'], json_in['match_key'], os.path.join(cache_folder, CACHE_CONST), json_in['red_relative_keys'], fout=filename)

    # Put File on Firebase
    storage.child('/')
    storage.child(full_path).put(full_path)

    return flask.send_file(filename_or_fp=full_path, mimetype='image/png')
# attachment_filename=os.path.join(cache_folder, CACHE_CONST, filename),

    # pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# def create_access_token(*, data: dict, expires_delta: timedelta = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
#     return encoded_jwt
# def get_secret(token: str):
#     try:
#         payload = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
#     except:
#         raise Exception()
#     return payload
if __name__ == '__main__':
    storage = firebase.storage()
    app.run()
ssl_context = ('cert.pem', 'key.pem')
