
# encoding = utf-8
# Always put this line at the beginning of this file
import misp42splunk_declare
import sys

from alert_actions_base import ModularAlertBase
import modalert_misp_alert_create_event_helper


class AlertActionWorkermisp_alert_create_event(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(
            AlertActionWorkermisp_alert_create_event,
            self
        ).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("title"):
            self.log_error(
                'title is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("distribution"):
            self.log_error(
                'distribution is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("threatlevel"):
            self.log_error(
                'threatlevel is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("analysis"):
            self.log_error(
                'analysis is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("tlp"):
            self.log_error(
                'tlp is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("pap"):
            self.log_error(
                'pap is a mandatory parameter, but its value is None.'
            )
            return False

        if not self.get_param("misp_instance"):
            self.log_error(
                'misp_instance is a mandatory parameter, \
                but its value is None.'
            )
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_misp_alert_create_event_helper.process_event(
                self,
                *args,
                **kwargs
            )
        except (AttributeError, TypeError) as ae:
            self.log_error(
                "Error: {}. Please double check spelling and also verify that \
                a compatible version of Splunk_SA_CIM is \
                installed.".format(ae.message)
            )
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            self.log_error(msg.format(e))
            # if e.message:
            #     self.log_error(msg.format(e.message))
            # else:
            #     import traceback
            #     self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status


if __name__ == "__main__":
    exitcode = AlertActionWorkermisp_alert_create_event(
        "misp42splunk",
        "misp_alert_create_event"
    ).run(sys.argv)
    sys.exit(exitcode)
