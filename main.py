from flask import request, abort, jsonify, json, render_template
import flask
from flask_cors import CORS
import requests
from datetime import datetime
import os
import re

app = flask.Flask(__name__)
CORS(app)
app.Debug = False

f = open("api_keys.txt","r")
stored_keys = f.read()

cache_folder = os.path.join(os.path.dirname(__file__),'cache')

BASE_API_URL = "https://www.thebluealliance.com/api/v3"
API_KEY = os.getenv("TBA_KEY")

def check_key(key):
  return key in stored_keys

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
def write_to_file(data,file_path,filename):
  if not os.path.exists(file_path):
      os.makedirs(file_path)
  f = open(os.path.join(file_path,filename), 'w')
  f.write(str(datetime.utcnow().strftime('%c'))+'\n'+json.dumps(data))

def get_teams(year, CACHE_CONST):
  filename = str(year) + '.txt'
  txt, update = update_cache(os.path.join(cache_folder,CACHE_CONST,filename))
  if not update:
    return txt 

  all_data = []
  pg = 0
  while True:
    r = requests.get(url=os.path.join(BASE_API_URL,"teams", str(year) ,
                      str(pg), 'simple'), headers=auth_headers())
    r = r.json()
    if len(r) == 0:
      write_to_file(all_data,os.path.join(cache_folder,CACHE_CONST),filename)
      return all_data
    for data in r:
        all_data.append(simplify_data(data))
    pg += 1

@app.route('/', methods=['GET'])
def main():
  return render_template('index.html')

@app.route('/teams', methods=['POST'])
def teams():
  CACHE_CONST = 'teams'
  json_in = request.json
  if not check_key(json_in['API-Key']):
    return jsonify(["Not Allowed, please use a valid API Key"]), 403
  return jsonify(get_teams(json_in['year'], CACHE_CONST)), 200

@app.route('/event/teams', methods = ['POST'])
def event_teams():
  CACHE_CONST='events'
  json_in = request.json
  if not check_key(json_in['API-Key']):
    return jsonify(["Not Allowed, please use a valid API Key"]), 403
  r = requests.get(url=os.path.join(BASE_API_URL,'event', json_in['event_key'], 'teams'), headers=auth_headers())
  if r.status_code == 404:
    abort(404)
  
  filename = json_in['event_key'] + '.txt'
  txt,  update =  update_cache(os.path.join(cache_folder,CACHE_CONST,filename))
  if not update:
    return jsonify(txt) , 200
  all_data = []
  r = r.json()
  for item in r:
    all_data.append(simplify_data(item))
  write_to_file(all_data,os.path.join(cache_folder,CACHE_CONST),filename)

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

@app.route('/event/matches', methods = ['POST'])
def get_matches():
  CACHE_CONST = 'events'
  json_in = request.json
  if not check_key(json_in['API-Key']):
    return abort(403)
  r = requests.get(url=os.path.join(BASE_API_URL,'event', json_in['event_key'], 'matches', 'simple'), headers=auth_headers())
  if r.status_code == 404:
    abort(404)

  filename = json_in['event_key'] + '.matches.' + json_in['match_type']+ '.txt'

  REGEX_PATTERN = re.compile("(^\w+_" + json_in['match_type'] + "\d+)$")

  txt, update = update_cache(os.path.join(cache_folder, CACHE_CONST,filename))

  if not update:
    print('no update')
    return jsonify(txt),200
  
  all_data = {}
  r = r.json()
  for item in r:
    if REGEX_PATTERN.match(item['key']):
      match_data = {}
      all_data[item['match_number']]= match_data
      alliances = item['alliances']
      match_data['blue']= process_team_keys(alliances['blue']['team_keys'])
      match_data['red']= process_team_keys(alliances['red']['team_keys'])
      
  return jsonify(all_data), 200

if __name__ == '__main__' :
    # host='0.0.0.0'
 app.run(port=8080)