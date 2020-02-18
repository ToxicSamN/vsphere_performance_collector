
import json
from datetime import datetime
from vspherecollector.vmware.rest.client import ApplianceAPI
from vspherecollector.log.setup import addClassLogger


class Service(object):

    def __init__(self, service_dict):
        self.name = service_dict['key']
        self.key = service_dict['value'].get('name_key' or None)
        self.startup_type = service_dict['value'].get('startup_type' or None)
        self.health_messages = service_dict['value'].get('health_messages' or [])
        self.health = service_dict['value'].get('health' or None)
        self.description_key = service_dict['value'].get('description_key' or None)
        self.state = service_dict['value'].get('state' or None)


@addClassLogger()
class VCSAService(ApplianceAPI):

    def __init__(self, cim_session):
        self.session = cim_session
        self.services = []
        super().__init__(cim_session.vcenter)

        self.base_url += 'vmon/service'

    def get_status(self, service) -> dict:
        url = self.base_url + f'/{service}'
        self.__log.info(f'Collecting status for service: {service}')
        self.session.get(url)
        return self._parse_services()

    def list_all_services(self) -> dict:
        self.__log.info(f'Collecting status for all services in vCenter {self.session.vcenter}')
        self.session.get(self.base_url)
        return self._parse_services()

    def _parse_services(self) -> dict:
        dt = datetime.now()
        d = json.loads(self.session.response.content.decode())
        self.__log.debug(f'Parsing results: {d}')

        influx_json = {
            'time': dt,
            'measurement': 'vcServices',
            'fields': {

            },
            'tags': {
                'vcenter': self.session.vcenter
            }
        }

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
