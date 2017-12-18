#!/usr/bin/env python
#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
# -*- coding: utf-8 -*-

from pymisp import PyMISP
import urllib3

def init(url, key, ssl):
    return PyMISP(url, key, ssl, 'json')

try:
    my_args = eval(sys.argv[1])
    event   = eval(sys.argv[2])
except:
    pass

mispsrv  = my_args['mispsrv']
mispkey  = my_args['mispkey']
sslcheck = my_args['sslcheck']

filename = '/opt/splunk/etc/apps/misp42splunk/bin/test.json'
with open('filename.txt', 'w') as file_object:
    file_object.write("I test pymisp")
    file_object.write(my_args)
print(my_args)


'''
try:
        misp = init(mispsrv, mispkey, False)
except:
        exit(1)


if 'eventid' in my_args:
        print(str(get_event(misp, my_args['eventid'])))
elif 'last' in my_args:
        print(str(get_last(misp, my_args['last'])))
else:
        exit(1)

exit(0)


if __name__ == '__main__':
    misp = init(misp_url, misp_key)
    event = misp.new_event(args.distrib, args.threat, args.analysis, args.info)
    print(event)
'''