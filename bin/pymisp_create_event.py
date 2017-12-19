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
import os, sys, json, time

def init(url, key, ssl):
    return PyMISP(url, key, ssl, 'json')

try:
    config = eval(sys.argv[1])
    event  = eval(sys.argv[2])


    mispsrv  = config['mispsrv']
    mispkey  = config['mispkey']
    sslcheck = config['sslcheck']

    analysis = config['analysis']
    distrib  = config'distribution']
    threat   = config['threatlevel']
    tlp      = config['tlp']

    date    = event['timestamp']
    info    = event['info']

except:
    pass


try:
    misp = init(mispsrv, mispkey, False)

#def new_event(self, distribution=None, threat_level_id=None, analysis=None, info=None, date=None, published=False, orgc_id=None, org_id=None, sharing_group_id=None):
    my_event = new_event(distrib, threat, analysis, info, date)

#def add_named_attribute(self, event, type_value, value, category=None, to_ids=False, comment=None, distribution=None, proposal=False, **kwargs):
    for attribute in event['attribute']:
        my_event = add_named_attribute(my_event, attribute['type'], attribute['value'], attribute['category'], attribute['to_ids'] )

except:
    exit(1)


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




if 'eventid' in config:
        print(str(get_event(misp, config['eventid'])))
elif 'last' in config:
        print(str(get_last(misp, config['last'])))
else:
        exit(1)

exit(0)


if __name__ == '__main__':
    misp = init(misp_url, misp_key)
    event = misp.new_event(args.distrib, args.threat, args.analysis, args.info)
    print(event)
'''