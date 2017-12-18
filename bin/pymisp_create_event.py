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
def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
        """Create and add a new event"""
        misp_event = self._prepare_full_event(distribution, threat_level_id, analysis, info, date, published, orgc_id, org_id, sharing_group_id)
        return self.add_event(misp_event)

    def tag(self, uuid, tag):
        """Tag an event or an attribute"""
        if not self._valid_uuid(uuid):
            raise PyMISPError('Invalid UUID')
        url = urljoin(self.root_url, 'tags/attachTagToObject')
        to_post = {'uuid': uuid, 'tag': tag}
        response = self.__prepare_request('POST', url, json.dumps(to_post))
return self._check_response(response)

def add_named_attribute(self, event, type_value, value, category=None, to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
        """Add one or more attributes to an existing event"""
        attributes = []
        for value in self._one_or_more(value):
            attributes.append(self._prepare_full_attribute(category, type_value, value, to_ids, comment, distribution, **kwargs))
return self._send_attributes(event, attributes, proposal)


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