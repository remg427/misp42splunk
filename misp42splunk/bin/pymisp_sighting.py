#!/usr/bin/python3
#
# Extract IOC's from MISP
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
import sys
# import json
from pymisp import PyMISP

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def init(url, key, ssl):
    return PyMISP(url, key, ssl, 'json')


def set_sighting(m, s):
    return m.set_sightings(s)


try:
    config = eval(sys.argv[1])
    sighting = eval(sys.argv[2])

    misp_url = config['misp_url']
    misp_key = config['misp_key']
    misp_verifycert = config['misp_verifycert']

    # connect to misp instance using misp_url, misp_key and boolean misp_verifycert
    misp = init(misp_url, misp_key, misp_verifycert)

    # byvalue: sighting contains {"timestamp": timestamp, "values":["value1", "value2,etc. "]}
    # byuuid:  sighting contains {"timestamp": timestamp, "uuid":"uuid_value"}
    set_sighting(misp, sighting)

except IOError as e:
    print("Error in pymisp_sighting.py")
    exit(1)
