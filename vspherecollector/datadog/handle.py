
import logging
import json
import time, datetime
import os
import base64
import requests
import uuid
import queue
from .exceptions import *
from .encryption import AESCipher
from vspherecollector.log.setup import addClassLogger
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from vspherecollector.vmware.credentials.credstore import Credential


logger = logging.getLogger(__name__)


@addClassLogger
class Datadog(object):

    def __init__(self, config_file, bg_process=False, ddq=None):
        if bg_process and not ddq:
            raise ValueError('Datadog cannot run with bg_procees without a ddq object')
        self.__api_key = None
        self.__application_key = None
        self.datadog_base_url = 'https://api.datadoghq.com/api/v1/'
        requests.adapters.DEFAULT_RETRIES = 3
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Content-type': 'application/json'
        })
        self.proxies = None
        disable_warnings(InsecureRequestWarning)
        self.api_response = None
        self.config_file = config_file
        self.__cipher = AESCipher()

        self.setup_connection(config_file)
        if bg_process:
            self.in_q = ddq
            try:
                self.__run()
            except BaseException as e:
                self.logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    def __get_api_key(self):
        return self.__decode_key(self.__api_key)

    def __store_api_key(self, api_key):
        self.__api_key = self.__encode_key(api_key)

    def __get_app_key(self):
        return self.__decode_key(self.__application_key)

    def __store_app_key(self, app_key):
        self.__application_key = self.__encode_key(app_key)

    def __encode_key(self, plaintxt):
        """
        This is purely obfuscation and not actually secure. but for the purposes for this project, this will do.
        :param string:
        :return: encoded string
        """
        return self.__cipher.encrypt(plaintxt)

    def __decode_key(self, enc_txt):
        return self.__cipher.decrypt(key=self.__cipher.AES_KEY, enc=enc_txt)

    def setup_connection(self, config_file):
        """
        Reads in the config file to get the API Key and App Key and and proxies that may be defined
        :param config_file:
        :return:
        """
        try:
            if not os.path.exists(config_file):
                raise FileExistsError('File path {} not found.'.format(config_file))
            self.config_file = config_file
            self.__log.info('Loading the Datadog config data')
            with open(config_file) as json_file:
                data = json.load(json_file)
                json_file.close()
            self.__log.debug(data.__str__())
            if data.get('api_key' or None):
                self.__store_api_key(data['api_key'])
            else:
                _cred = Credential(username='datadog_api_key')
                self.__store_api_key(_cred.get_credential()['password'])
                if not self.__api_key:
                    raise DatadogApiKeyError(
                        "Unable to locate Datadog API Key in file {} or from https://credstore".format(config_file))

            if data.get('app_key' or None):
                self.__store_app_key(data['app_key'])

            if data.get('proxies' or None):
                self.proxies = data['proxies']

        except BaseException as e:
            self.__log.exception('Exception: {} \n Args: {}'.format(e, e.args))
            raise e

    def __run(self):
        self.__log.info('Datadog process Started')
        queue_empty_flag = 1
        while True:
            try:
                json_data = self.in_q.get_nowait()
                queue_empty_flag = 0
                if json_data:

                    try:
                        if isinstance(json_data, list):
                            datadog_retired = True
                            # self.post_metric({'series': json_data})

                    except BaseException as e:
                        # Writing to Datadog was unsuccessful. For now let's just try to resend
                        self.__log.error('Failed to Send datadog data {}'.format(json_data))
                        self.__log.info('Retry Sending stats: {}'.format(json_data))
                        self.logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
                        # self.post_metric({'series': json_data})

                        pass
            except queue.Empty:
                if queue_empty_flag == 0:
                    self.__log.info("Datadog Complete")
                    queue_empty_flag = 1
                pass
            except BaseException as e:
                self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))

        logger.info('Datadog process Stopped')

    def post_event(self, title, text, date_happened=datetime.datetime.now(), priority='normal', host='', tags=None,
                   alert_type='info', aggregation_key='', source_type_name='', related_event_id='',
                   device_name=''):
        """
        This method is matching that of the Datadog API documentation
        :param title: required parameter
        :param text: required parameter
        :param date_happened: required parameter, defaults to datetime.now()
        :param priority:
        :param host:
        :param tags:
        :param alert_type:
        :param aggregation_key:
        :param source_type_name:
        :param related_event_id:
        :param device_name:
        :return:
        """
        try:

            json_payload = {
                'title': "{}".format(title),
                'text': "{}".format(text),
                'date_happened': self._convert_to_epoch(date_happened),
            }
            if priority:
                json_payload.update({'priority': "{}".format(priority)})

            if host:
                json_payload.update({'host': "{}".format(host)})

            if tags:
                json_payload.update({'tags': tags})

            if alert_type:
                json_payload.update({'alert_type': "{}".format(alert_type)})

            if aggregation_key:
                json_payload.update({'aggregation_key': "{}".format(aggregation_key)})

            if source_type_name:
                json_payload.update({'source_type_name': "{}".format(source_type_name)})

            if related_event_id:
                json_payload.update({'related_event_id': related_event_id})

            if device_name:
                json_payload.update({'device_name': "{}".format(device_name)})

            url = "{}{}".format(self.datadog_base_url, 'events?api_key={}'.format(self.__get_api_key()))
            self.api_response = self.session.post(url=url, json=json_payload, timeout=1.0, proxies=self.proxies)
            self.validate_api_response()

        except BaseException as e:
            self.__log.exception('Exception: {} \n Args: {}'.format(e, e.args))
            raise e

    @staticmethod
    def _convert_to_epoch(date_time):
        if isinstance(date_time, datetime.datetime):
            return time.mktime(date_time.timetuple())

        raise TypeError("date_time parameter must be type 'datetime.datetime'")

    def post_metric(self, json_data):
        """
        Work in progress, not production ready
        :param json_data:
        :return:
        """
        try:
            if not self.validate_metric_json(json_data):
                raise ValueError("metric json_data must contain valid data. \n"
                                 "See documentation at https://docs.datadoghq.com/api/?lang=bash#post-timeseries-points")
            url = "{}{}".format(self.datadog_base_url, 'series?api_key={}'.format(self.__get_api_key()))
            self.api_response = self.session.post(url=url, data=json.dumps(json_data), proxies=self.proxies)
            self.validate_api_response()

        except BaseException as e:
            self.__log.exception('Exception: {} \n Args: {}'.format(e, e.args))
            raise e

    def post_logs(self, method, data, tags=None):
        """
        Work in progress, not production ready
        :param method:
        :param data:
        :param tags:
        :return:
        """
        try:
            if method.lower() == 'post':
                url = "{}{}".format(self.datadog_base_url, 'input?api_key={}'.format(self.__get_api_key()))
                self.api_response = self.session.get(url=url)

                self.validate_api_response()

        except BaseException as e:
            self.__log.exception('Exception: {} \n Args: {}'.format(e, e.args))
            raise e

    @staticmethod
    def validate_metric_json(json_data):
        if json_data.get('series' or None):
            series = json_data['series']
            # validate required parameters
            for s in series:
                if s.get('metric' or None) and s.get('points' or None):
                    if isinstance(s['points'], list):
                        # points should be a list of lists
                        for val in s['points']:
                            if not isinstance(val, list) and not isinstance(val, tuple):
                                return False
                else:
                    return False
            return True
        return False

    def validate_api_response(self):
        self.__log.debug('Validating api response')
        self.__log.debug("HTTP Response: {}".format(self.api_response.status_code))
        try:
            self.api_response.raise_for_status()
            self.__log.debug('API Response OK')
        except requests.exceptions.HTTPError as e:
            self.__log.exception('Exception: {}'.format(e))
            raise e
