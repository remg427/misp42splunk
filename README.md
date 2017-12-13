# misp42splunk
A Splunk app to use MISP in background

# Credits
This app is largely inspired by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/

# Prerequisites
1. Install Python 3 on the Splunk Search Head
2. Check that python3 is at /usr/bin/python3

    + if not you may create a symbolic link to the python3.x binary
    + alternatively you may edit misp42splunk/bin/misp-get-ioc.py and adjuut the path to your environment

3. Install PyMISP (see https://github.com/CIRCL/PyMISP)
4. Check that your Splunk SH can connect to the MISP instance. 

# Installation
1. Download the zip file and install the app on your splunk search head (you may remove -master from file name)
2. A custom endpoint has been defined so you will need to restart Splunk (for later updates you may skip this part)
3. At next logon, you should be invited to configure the app (if not goto Manage Apps > TA-MISP 42 Spliunk > Set up) 

    - provide the url to your MISP instance
    - provide the authkey 
    - [not implemented] check the certificate of the MISP server

# Usage

## mispgetioc
This custom command must be the first of a search (or a sub-search). The results are displayed in a table.
The command syntax is as follow:

    |mispgetioc [server=https://host:port] 
                [authkey=misp-authorization-key]
                [sslcheck=y|n]
                [eventid=id]
                [last=interval]
                [onlyids=y|n]
                [category=string]
                [type=string]
                
# Todo
- implement sslcheck boolean
- implemet alert_action
- store some saved searches as examples

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0
