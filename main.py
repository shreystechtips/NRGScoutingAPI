from flask import request, abort, jsonify, json, render_template
import flask
from flask_cors import CORS
import requests
from datetime import datetime, timedelta
import os
import re
import jwt
from passlib.context import CryptContext
from binascii import hexlify
from flask_bcrypt import Bcrypt
import psycopg2
from dotenv import load_dotenv
load_dotenv()

app = flask.Flask(__name__)
CORS(app)
app.Debug = False
bcrypt = Bcrypt(app)
SECRET = os.getenv("SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 3

cache_folder = os.path.join(os.path.dirname(__file__), 'cache')

BASE_API_URL = "https://www.thebluealliance.com/api/v3"
API_KEY = os.getenv("TBA_KEY")


con = psycopg2.connect(os.getenv("DB_URL"), sslmode='require')


cur = con.cursor()
postgres_insert_query = """ INSERT INTO users (email, password, team, auth_key) VALUES (%s,%s,%s,%s)"""
postgres_exists_query = """ select * from users where {0} = {2}{1}{2} """


def check_key(key):
    print(key)
    cur.execute(postgres_exists_query.format(
        'auth_key', 'b\'\'' + key + '\'\'', '\''))
    return not cur.fetchone() == None


def auth_headers():
    return {'X-TBA-Auth-Key': API_KEY}


def simplify_data(data):
    temp = {'team_number': data['team_number'], "nickname": data['nickname']}
    return temp


def update_cache(path):
    if os.path.isfile(path):
        yearfile = open(path)
        try:
            date_file = datetime.strptime(yearfile.readline().strip(), '%c')
            if (datetime.utcnow()-date_file).days < 7:
                return json.loads(yearfile.readline()), False
        except:
            print('')
    return [], True

# Overwrites file with current time and stringifys the json


def write_to_file(data, file_path, filename):
    if not os.path.exists(file_path):
        os.makedirs(file_path)
    f = open(os.path.join(file_path, filename), 'w')
    f.write(str(datetime.utcnow().strftime('%c'))+'\n'+json.dumps(data))


def get_teams(year, CACHE_CONST):
    filename = str(year) + '.txt'
    txt, update = update_cache(os.path.join(
        cache_folder, CACHE_CONST, filename))
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
    return render_template('index.html', message="")


@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
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
            return render_template('index.html', message="Successfully signed up! Log in to see API key")
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
            print(temp[3])
            message = "Your API Key is: " + \
                str(temp[3])[2:len(temp[3])-1] + \
                " DO NOT SHARE IT with anyone!"
        else:
            message = "Incorrect username or password"
    return render_template('login.html', message=message)


@app.route('/teams', methods=['POST'])
def teams():
    CACHE_CONST = 'teams'
    json_in = request.json
    if not check_key(json_in['API-Key']):
        return jsonify(["Not Allowed, please use a valid API Key"]), 403
    return jsonify(get_teams(json_in['year'], CACHE_CONST)), 200


@app.route('/event/teams', methods=['POST'])
def event_teams():
    CACHE_CONST = 'events'
    json_in = request.json
    if not check_key(json_in['API-Key']):
        return jsonify(["Not Allowed, please use a valid API Key"]), 403
    r = requests.get(url=os.path.join(BASE_API_URL, 'event',
                                      json_in['event_key'], 'teams'), headers=auth_headers())
    if r.status_code == 404:
        abort(404)

    filename = json_in['event_key'] + '.txt'
    txt,  update = update_cache(os.path.join(
        cache_folder, CACHE_CONST, filename))
    if not update:
        return jsonify(txt), 200
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


# Takes parameters: API-Key, event_key, comp_level
@app.route('/event/matches', methods=['POST'])
def get_matches():
    CACHE_CONST = 'events'
    json_in = request.json
    if not check_key(json_in['API-Key']):
        return abort(403)
    r = requests.get(
        url=os.path.join(BASE_API_URL, 'event', json_in['event_key'],
                         'matches', 'simple'),
        headers=auth_headers())
    if r.status_code == 404:
        abort(404)

    filename = json_in['event_key'] + '.matches.' + json_in[
        'comp_level'] + '.txt'

    REGEX_PATTERN = re.compile("(^\w+_" + json_in['comp_level'] + "\d+)$")

    txt, update = update_cache(
        os.path.join(cache_folder, CACHE_CONST, filename))

    if not update:
        print('no update')
        return jsonify(txt), 200

    all_data = {}
    r = r.json()
    for item in r:
        if item['comp_level'] == json_in['comp_level']:
            match_data = {}
            all_data[str(item['set_number']) + ',' +
                     str(item['match_number'])] = match_data
            alliances = item['alliances']
            match_data['blue'] = process_team_keys(
                alliances['blue']['team_keys'])
            match_data['red'] = process_team_keys(
                alliances['red']['team_keys'])

    return jsonify(all_data), 200


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
    app.run()
