import queue
import logging
import dns.resolver
import time
from dns.resolver import NXDOMAIN
from pyVmomi import SoapAdapter, vim
from dateutil import parser as timeparser
from datetime import datetime
from vspherecollector.statsd.agent import QueryResult
from vspherecollector.log.setup import addClassLogger


# LOGGERS = Logger(log_file='/var/log/vcenter_collector/parser.log',
#                  error_log_file='/var/log/vcenter_collector/parser_err.log')


class SampleInfo:

    def __init__(self, interval, timestamp):
        self.sample_interval = interval
        self.sample_time = timestamp


@addClassLogger
class Parser:

    def __init__(self, statsq, influxq, datadogq):
        self.in_q = statsq
        self.out_q = influxq
        self.dd_q = datadogq

        self._run()

    def _run(self):
        """
        This is the background process payload. Constantly looking in the statsq
        queue to be able to parse the data to json.
        :return: None
        """

        self.__log.info('Parser process Started')
        data_series = []
        queue_empty_flag = 1
        # running as a background process and should be in an infinite loop
        while True:
            try:
                # get the next item in the queue
                data = self.in_q.get_nowait()
                # logger.debug('data pulled from queue : {}'.format(data))
                # send the raw data to be parsed into a dict format
                queue_empty_flag = 0

                json_series = self._parse_data(data)
                if json_series:

                    # since the influxdb process is using queues and is also a background
                    # process lets parse the array of dicts down to single entries into the queue
                    # to be processed by influx

                    if isinstance(json_series, list):
                        for i in json_series:
                            # logger.info('Parsed JSON data: {}'.format(i.__str__()))
                            self.out_q.put_nowait(i)

            except queue.Empty:
                if queue_empty_flag == 0:
                    self.__log.debug("Parser Complete")
                    queue_empty_flag = 1
                # keep looping waiting for the queue not to be empty

                #   code reviewer...this is a test to see if you actually reviewed the code
                #     did you see this comment? If so you might win a prize, let me know!
                pass
            except BaseException as e:
                self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    def _parse_data(self, data):
        """
        this function prepares the data to be sent to _format_json
        :param data:
        :return: json_series
        """

        try:
            self.__log.debug('_data_parser parsing data {}'.format(data))
            vcenter_name = list(data.keys())[0]
            data = data[vcenter_name]
            datacenter = data['datacenter']
            cluster = data['cluster']
            ds_map = data['ds_map']
            results = data['result']
            inf_env = data['inf.env']
            inf_role = data['inf.role']
            inf_security = data['inf.security']
            self.__log.debug('vcenter: {}, dc: {}, cl: {}\nresults: {}'.format(vcenter_name,
                                                                               datacenter,
                                                                               cluster,
                                                                               results))
            self.__log.debug('sending to prep_n_send_data')
            json_series = self._prep_n_send_data(datum=results,
                                                 vcenter=vcenter_name,
                                                 datacenter=datacenter,
                                                 cluster=cluster,
                                                 ds_map=ds_map,
                                                 inf_env=inf_env,
                                                 inf_role=inf_role,
                                                 inf_security=inf_security)
            self.__log.debug("json_series size: {}".format(len(json_series)))

            return json_series

        except BaseException as e:
            self.__log.error('Parsing error: \nvCenter: {}'.format(vcenter_name))
            self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    @staticmethod
    def _parse_sample_data(sample_csv):
        logger = logging.getLogger('{}.Parser.parse_sample_data'.format(__name__))
        try:
            samplecsv = sample_csv.split(',')
            sample_info = [SampleInfo(samplecsv[index], timeparser.parse(samplecsv[index + 1])) for index
                           in
                           range(int(len(samplecsv))) if index % 2 == 0]
            return sample_info
        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
        return None

    def _prep_n_send_data(self, datum, vcenter, datacenter, cluster, ds_map={}, inf_env=None, inf_role=None,
                          inf_security=None):
        """
        :param datum:
        :param vcenter:
        :return: json_series
        """

        try:
            self.__log.debug('datum type: {}, datum: {}'.format(type(datum), datum))
            json_series = []
            datadog_series = []
            if isinstance(datum, QueryResult):
                self.__log.debug('datum is QueryResult')
                data = datum
                self.__log.debug('build meta lookup dict')
                for metric in data.stat_value_csv:
                    if metric.metric_instance is None or metric.metric_instance == '':
                        metric.metric_instance = 'all'
                    if ds_map.get(metric.metric_instance or None):
                        metric.metric_instance = ds_map[metric.metric_instance]
                meta_lookup = self.get_meta(data.stat_value_csv)
                sample_data = self._parse_sample_data(data.sample_info_csv)
                self.__log.debug('Meta_lookup: {}, sample_data: {}'.format(meta_lookup, sample_data))
                for meta in list(meta_lookup.keys()):
                    self.__log.debug('Meta: {}'.format(meta))
                    for instance in list(meta_lookup[meta].keys()):
                        self.__log.debug('metric instance: {}'.format(instance))
                        hostname = ''
                        if data.moref_type == 'HOST' or data.moref_type == 'VM':
                            hostname = self._get_fqdn(data.moref_name.lower())

                        tags = {
                            "host": str(data.moref_name.lower()),  # this should be renamed to entity
                            # "entity": str(data.moref_name.lower()),
                            "location": str(datacenter),
                            "type": str(data.moref_type),
                            "cluster": str(cluster),
                            "vcenter": str(vcenter),
                            "instance": str(instance),
                        }

                        datadog_tags = {
                            'inf.tools.host': str(hostname.lower()),
                            'vsphere_entity': str(data.moref_name.lower()),
                            'app': 'vsphere',
                            'team': 'cig',
                            'instance': str(instance),
                            'vsphere_cluster': str(cluster),
                            'vsphere_datacenter': str(datacenter),
                            'vsphere_type': str(data.moref_type.lower()),
                            'vcenter_server': str(vcenter),
                            'inf.vsphere.env': inf_env,
                            'inf.vsphere.role': inf_role,
                            'inf.vsphere.security': inf_security
                        }
                        self.__log.debug('tags: {}'.format(tags))
                        self.__log.debug('Datadog tags: {}'.format(datadog_tags))
                        json_data = []
                        for index in meta_lookup[meta][instance]:
                            _data = data.stat_value_csv[index]
                            datadog_series.append(self._format_datadog_json(_data, datadog_tags, sample_data))
                            json_data = self._format_json(meta, _data, tags, sample_data, json_data)

                        json_series.append(json_data)
            else:
                raise TypeError('Unexpected type: {}. Requires type: {}'.format(type(datum), QueryResult))

            self.dd_q.put_nowait(datadog_series)
            return json_series

        except BaseException as e:
            self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))

        return None

    @staticmethod
    def _format_json(measurement, metric, tags, sample_data, json_series=[]):
        logger = logging.getLogger('{}.Parser.format_json'.format(__name__))
        logger.debug('starting _format_json: measurement: {}, tags: {}'.format(measurement, tags))
        try:
            _json_series = []
            if not isinstance(tags, dict):
                raise TypeError("Parameter 'tags' expected type dict but received type '{}'".format(type(tags)))

            for data in zip(metric.metric_value_csv.split(','), sample_data):
                sample_time = datetime.utcfromtimestamp(data[1].sample_time.timestamp())
                influx_time = sample_time.__str__()
                val = data[0]

                if metric.metric_name == "cpu.ready.summation":
                    # CPU Ready is calculated as
                    # time_in_ms / (sample_interval *1000) and then multiply by 100 to get %
                    percent_ready = (float(val) / (float(sample_data[0].sample_interval) * 1000)) * 100
                    value = float(percent_ready)
                elif metric.metric_unit == 'percent':
                    value = float(val) / 100
                else:
                    if val is None or val == '':
                        value = float(0.0)
                    else:
                        value = float(val)
                if json_series:
                    for d in json_series:
                        if d['time'] == influx_time:
                            d['fields'].update({
                                str(metric.metric_name.replace("{}.".format(metric.metric_meta), '')): value,
                            })
                            break
                    _json_series = json_series
                else:
                    json_data = {
                        'time': influx_time,
                        'measurement': str(metric.metric_meta),
                        'fields': {
                            str(metric.metric_name.replace("{}.".format(metric.metric_meta), '')): value,
                        },
                        'tags': tags,
                    }
                    _json_series.append(json_data)
            logger.debug('json_data: {}'.format(_json_series))
            return _json_series
        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
        return None

    @staticmethod
    def _format_datadog_json(metric, tags, sample_data):
        sample_times = [s.sample_time.timestamp() for s in sample_data]
        json_series = {
            'metric': 'vsphere.{}'.format(metric.metric_name),
            'type': 'gauge',
            'points': list(zip(sample_times, metric.metric_value_csv.split(','))),
            'tags': tags.copy(),  # Need to copy this dict so that we can pop without affecting the original object
            'integration': 'vsphere',
            'unit': metric.metric_unit
        }
        if tags.get('inf.tools.host' or None):
            json_series.update({'host': tags['inf.tools.host']})
        else:
            json_series['tags'].pop('inf.tools.host')

        return json_series

    @staticmethod
    def get_meta(metric_list):
        logger = logging.getLogger('{}.Parser.get_meta'.format(__name__))
        try:
            meta_lookup = {}
            index_track = 0

            for metric in metric_list:
                if metric.metric_instance is None or metric.metric_instance == '':
                    metric.metric_instance = 'all'

                if meta_lookup.get(metric.metric_meta or None):
                    # meta exists, store the index number
                    if meta_lookup.get(metric.metric_meta).get(metric.metric_instance or None):
                        # entity instance exists, so update instance index
                        meta_lookup.get(metric.metric_meta).get(metric.metric_instance).append(index_track)
                    else:
                        # metric meta exists but not instance
                        meta_lookup.get(metric.metric_meta).update({str(metric.metric_instance): [index_track]})
                else:
                    # meta doesn't exist so have to create it
                    meta_lookup.update({metric.metric_meta: {str(metric.metric_instance): [index_track]}})

                index_track += 1
            logger.debug(meta_lookup.__str__())
            return meta_lookup
        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
        return None

    def _get_fqdn(self, name):
        fqdn = None
        try:
            dns_qry = dns.resolver.query(name)
            fqdn = dns_qry.canonical_name.__str__().strip('.')

        except NXDOMAIN as e:
            self.__log.warning(
                'Unable to locate a DNS record for {}.\nException: {} \n Args: {}'.format(name, e, e.args))

        return fqdn

    @staticmethod
    def _convert_to_epoch(date_time):
        if isinstance(date_time, datetime):
            return time.mktime(date_time.timetuple())