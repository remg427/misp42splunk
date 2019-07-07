# encoding = utf-8
# Always put this line at the beginning of this file
import misp42splunk_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_misp_alert_sighting_helper


class AlertActionWorkermisp_alert_sighting(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkermisp_alert_sighting, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("title"):
            self.log_error('title is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("mode"):
            self.log_error('mode is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("type"):
            self.log_error('type is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("misp_instance"):
            self.log_error('misp_instance is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_misp_alert_sighting_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(ae.message))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e.message:
                self.log_error(msg.format(e.message))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkermisp_alert_sighting("misp42splunk", "misp_alert_sighting").run(sys.argv)
    sys.exit(exitcode)
