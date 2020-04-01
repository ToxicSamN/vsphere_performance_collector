
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


@addClassLogger
class VCSAService(ApplianceAPI):

    def __init__(self, cim_session):
        self.session = cim_session
        self.services = []
        super().__init__(cim_session.vcenter)

        self.base_url += 'vmon/service'

    def get_status(self, service) -> list:
        url = self.base_url + f'/{service}'
        self.__log.info(f'Collecting status for service: {service}')
        self.session.get(url)
        return self._parse_services()

    def list_all_services(self) -> list:
        self.__log.info(f'Collecting status for all services in vCenter {self.session.vcenter}')
        self.session.get(self.base_url)
        return self._parse_services()

    def _parse_services(self) -> list:
        dt = datetime.utcnow()
        d = json.loads(self.session.response.content.decode())
        self.__log.debug(f'Parsing results: {d}')

        influx_json_series = []

        for s in d['value']:

            influx_json = {
                'time': dt,
                'measurement': f'vcServices.{s["key"]}',
                'fields': {
                    'started': 0,
                    'stopped': 0,
                    'healthy': 0,
                    'warning': 0,
                    'degraded': 0
                },
                'tags': {
                    'vcenter': self.session.vcenter
                }
            }

            '''
            Running State.
            Defines valid Run State for services. Value is one of:
            STARTING: Service Run State is Starting, it is still not functional. This constant was added in vSphere API 6.7
            STOPPING: Service Run State is Stopping, it is not functional. This constant was added in vSphere API 6.7
            STARTED: Service Run State is Started, it is fully functional. This constant was added in vSphere API 6.7
            STOPPED: Service Run State is Stopped. This constant was added in vSphere API 6.7
            '''
            started_value = 1 if (s['value']['state'].lower() == 'started') else 0
            stopped_value = 1 if (not s['value']['state'].lower() == 'started') else 0

            '''
            Startup Type.
            Defines valid Startup Type for services managed by vMon. Value is one of: 
            MANUAL: Service Startup type is Manual, thus issuing an explicit start on the service will start it. 
            AUTOMATIC: Service Startup type is Automatic, thus during starting all services or issuing explicit start on the service will start it. 
            DISABLED: Service Startup type is Disabled, thus it will not start unless the startup type changes to manual or automatic
            
            Health of service.
            Defines the possible values for health of a service. Value is one of: 
            DEGRADED: Service is in degraded state, it is not functional. 
            HEALTHY: Service is in a healthy state and is fully functional. 
            HEALTHY_WITH_WARNINGS: Service is healthy with warnings.Optional. It is only relevant when state has value STARTED.
            '''
            # -1 indicates no health information available
            healthy_value = -1
            warn_value = -1
            degrade_value = -1
            if s['value'].get('health' or False):
                # health value exists, means service should be started
                healthy_value = 1 if s['value']['health'].lower() == "healthy" else 0
                warn_value = 1 if s['value']['health'].lower() == "healthy_with_warnings" else 0
                degrade_value = 1 if s['value']['health'].lower() == "degraded" else 0

            influx_json['fields']['started'] = started_value
            influx_json['fields']['stopped'] = stopped_value
            influx_json['fields']['healthy'] = healthy_value
            influx_json['fields']['warning'] = warn_value
            influx_json['fields']['degraded'] = degrade_value

            influx_json_series.append(influx_json)

        return influx_json_series
