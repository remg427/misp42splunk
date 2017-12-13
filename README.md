# misp42splunk
A Splunk app to use MISP in background

# Credits 
# Prerequisites

    Install Python 3 on the Splunk server
    Install PyMISP (see https://github.com/CIRCL/PyMISP)

Installation

    Copy get-ioc-misp.py & mispconfig.py in /usr/local/bin

    Edit mispconfig.py and specify your MISP URL and authorization key

    Copy getiocmisp.py in /opt/splunk/etc/apps//bin/

    Copy the commands.conf or change the existing one in /opt/splunk/etc/apps//local/

    Restart Splunk

Usage
