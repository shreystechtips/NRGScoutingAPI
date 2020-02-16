import os
import base64
from dotenv import load_dotenv
from flask import render_template
from binascii import hexlify

import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib import use
from scipy import ndimage

import requests
import json

import requests
load_dotenv()
BASE_API_URL = "https://www.thebluealliance.com/api/v3"
use('Agg')
API_KEY = os.getenv("TBA_KEY")
STATIC_DATA = 'static/'


def auth_headers():
    return {'X-TBA-Auth-Key': API_KEY}


def generate_google_service(fileName):
    open(fileName, "w+").write(base64ToString(os.getenv("FIREBASE_SERVICE_CODE")))
    return fileName


def base64ToString(b):
    return base64.b64decode(bytes(b, "utf-8").decode('unicode_escape')).decode('utf-8')


def stringToBase64(s):
    return base64.b64encode(s.encode('utf-8'))


def render_doc_template(route):
    return render_template('endpoints.html', name=route, body=open('./templates/endpoints/' + route[1:].replace('/', '.')+'.txt').read())


def file_last_updated(url):
    header = requests.head(url, headers=auth_headers()).headers
    return header['Last-Modified']


def generate_zebra_coords(time, x, y):
    data = []
    for i in range(0, len(time)):
        data.append([time[i], x[i], y[i]])
    return data


def generate_zebra_csv(filepath, filename,  x, y, const_x=700/30, add_x=200, const_y=550/25, add_y=0):
    if not os.path.exists(filepath):
        os.makedirs(filepath)
    f = open(os.path.join(filepath, filename), 'w+')
    for i in range(0, len(x)):
        if (not x[i] == None):
            f.write(str(const_x*x[i] + add_x) + ' ' +
                    str(const_y*y[i] + add_y) + '\n')


def get_data(match_key, event_key, red_relative_keys, cache_path):
    r = requests.get(
        url=os.path.join(BASE_API_URL, 'match',
                         event_key + '_' + match_key, 'zebra_motionworks'),
        headers=auth_headers())
    if r.status_code == 404:
        None
    r = r.json()
    red_alliance = r['alliances']['red']
    blue_alliance = r['alliances']['blue']

    start = 1
    for alliance in red_alliance:
        if start in red_relative_keys:
            generate_zebra_csv(
                cache_path, str(
                    start) + '.txt', alliance['xs'], alliance['ys'])
        start += 1
    for alliance in blue_alliance:
        if start in red_relative_keys:
            generate_zebra_csv(cache_path, str(start) + '.txt',
                               alliance['xs'], alliance['ys'], add_x=0)
        start += 1


def plot_data(event_key, match_key, cache_path, red_relative_keys=range(1, 7), plot_line=False, fout=str(hexlify(os.urandom(16))) + ".png"):
    x = {}
    y = {}
    plots = {}
    color = ["Reds_r", "Oranges_r", "Purples_r",
             "Blues_r", "Greens_r", "Greys_r"]
    color_true = ["Reds", "Oranges", "Purples", "Blues", "Greens", "Greys"]
    get_data(match_key, event_key, red_relative_keys, cache_path)
    for i in red_relative_keys:
        x[i-1], y[i-1] = np.loadtxt(os.path.join(cache_path,
                                                 str(i) + '.txt'), unpack=True)
        # heatmap, xedges, yedges = np.histßogram2d(x[i-1], y[i-1], bins=20)
        plots[i-1] = sns.kdeplot(x[i-1], y[i-1], cmap=color[(i-1)],
                                 shade=False, shade_lowest=False, legend=True)
        if plot_line:
            plt.plot(x, y)
    im = plt.imread(os.path.join(STATIC_DATA, 'field', event_key[:4] + '.png'))
    rotated_img = ndimage.rotate(im, 180)
    plt.imshow(rotated_img, origin='upper', alpha=1)

    # extent = [xedges[0], xedges[-1], yedges[0], yedges[-1]]
    # plt.clf()
    # plt.imshow(heatmap.T, extent=extent, alpha=0)
    patches = []
    for plot in plots:
        col = color_true[(plot)]
        col = col[:len(col)-1]
        patches.append(mpatches.Patch(color=col, label=('Red' if int(plot/3)
                                                        == 0 else 'Blue') + ' ' + str((plot) % 3 + 1)))
    plt.legend(handles=patches, bbox_to_anchor=(0., 1.02, 1., .102), loc='lower left',
               ncol=2, mode="expand", borderaxespad=0.)
    axis = plt.gca()
    axis.set_xlim([0, 1400])
    axis.set_ylim([0, 600])
    plt.savefig(cache_path + fout, transparent=False,
                bbox_inches='tight', pad_inches=0)
    return True


# plot_data('2019cc', 'qm1', '', red_relative_keys=[2, 4],  fout='test.png')
