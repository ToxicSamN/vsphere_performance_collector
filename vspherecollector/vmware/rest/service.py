
import json
from datetime import datetime
from vspherecollector.vmware.rest.client import ApplianceAPI

class Service(object):

    def __init__(self, service_dict):
        self.name = service_dict['key']
        self.key = service_dict['value'].get('name_key' or None)
        self.startup_type = service_dict['value'].get('startup_type' or None)
        self.health_messages = service_dict['value'].get('health_messages' or [])
        self.health = service_dict['value'].get('health' or None)
        self.description_key = service_dict['value'].get('description_key' or None)
        self.state = service_dict['value'].get('state' or None)


class VCSAService(ApplianceAPI):

    def __init__(self, cim_session):
        self.session = cim_session
        self.services = []
        super().__init__(cim_session.vcenter)

        self.base_url += 'vmon/service'

    def get_status(self, service):
        url = self.base_url + f'/{service}'
        self.session.get(url)
        self._parse_services()

    def list_all_services(self) -> dict:
        self.session.get(self.base_url)
        return self._parse_services()

    def _parse_services(self) -> dict:
        dt = datetime.now()
        d = json.loads(self.session.response.content.decode())

        # time: time
        # measurement: vcServices
        # fields: [
        #     vpxd: status,
        #     vsan: status,
        #     webclient: status,
        # ]
        # tags: [
        #     vcenter: vcname,
        # ]
        # self.services = [Service(s) for s in d['value']]

        influx_json = {
            'time': dt,
            'measurement': 'vcServices',
            'fields': {

            },
            'tags': {
                'vcenter': self.session.vcenter
            }
        }
        # influx_json_2 = {
        #     'time': d,
        #     'measurement': '',
        #     'fields': {
        #         'state': '',
        #         'health': ''
        #     },
        #     'tags': {
        #         'vcenter': self.session.vcenter
        #     }
        # }

        for s in d['value']:
            ss = s["value"].get("state" or "NA")
            sh = s["value"].get("health" or "NA")

            if ss is None:
                ss = "NA"
            if sh is None:
                sh = "NA"

            influx_json['fields'].update({

                f'{s["key"]}_state': ss,
                f'{s["key"]}_health': sh
            })

        return influx_json
