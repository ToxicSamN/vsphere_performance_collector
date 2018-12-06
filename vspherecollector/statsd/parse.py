import queue
from dateutil import parser as timeparser
from datetime import datetime
from .collector import QueryResult
from .logging import Logger


LOGGERS = Logger(log_file='/var/log/vcenter_parser.log', error_log_file='/var/log/vcenter_parser_err.log')


class SampleInfo:

    def __init__(self, interval, timestamp):
        self.sample_interval = interval
        self.sample_time = timestamp


class Parser:

    def __init__(self, statsq, influxq):
        self.in_q = statsq
        self.out_q = influxq
        self.logger = LOGGERS.get_logger('Parser')

        self._run()

    def _run(self):
        """
        This is the background process payload. Constantly looking in the statsq
        queue to be able to parse the data to json.
        :return: None
        """
        # establish the logger
        logger = self.logger
        logger.info('Parser process Started')
        data_series = []
        queue_empty_flag = 1
        # running as a background process and should be in an infinite loop
        while True:
            try:
                # get the next item in the queue
                data = self.in_q.get_nowait()
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
                    logger.debug("Parser Complete")
                    queue_empty_flag = 1
                # keep looping waiting for the queue not to be empty

                #   code reviewer...this is a test to see if you actually reviewed the code
                #     did you see this comment? If so you might win a prize, let me know!
                pass
        logger.info('Parser process Stopped')

    def _parse_data(self, data):
        """
        this function prepares the data to be sent to _format_json
        :param data:
        :return: json_series
        """

        logger = LOGGERS.get_logger('Parser_data_parser')
        try:
            vcenter_name = list(data.keys())[0]
            data = data[vcenter_name]
            json_series = self._prep_n_send_data(datum=data, vcenter=vcenter_name)
            # logger.info("json_series size: {}".format(len(json_series)))

            return json_series

        except BaseException as e:
            logger.error('Parsing error: \nvCenter: {}'.format(vcenter_name))
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    @staticmethod
    def _parse_sample_data(sample_csv):
        samplecsv = sample_csv.split(',')
        sample_info = [SampleInfo(samplecsv[index], timeparser.parse(samplecsv[index + 1])) for index
                       in
                       range(int(len(samplecsv))) if index % 2 == 0]
        return sample_info

    def _prep_n_send_data(self, datum, vcenter):
        """
        :param datum:
        :param vcenter:
        :return: json_series
        """
        logger = self.logger
        json_series = []
        if isinstance(datum, list):
            for data in datum:
                sample_data = self._parse_sample_data(data.sample_info_csv)
                for metric in data.stat_value_csv:
                    if metric.metric_instance is None or metric.metric_instance == '':
                        metric.metric_instance = 'all'
                    tags = {
                        "host": str(data.moref_name.lower()),
                        "location": str(data.location),
                        "type": str(data.moref_type),
                        "cluster": str(data.cluster),
                        "vcenter": str(vcenter),
                        "instance": metric.metric_instance,
                    }
                    json_series.append(self._format_json(metric, sample_data, tags))

        elif isinstance(datum, QueryResult):
            data = datum
            meta_lookup = self.get_meta(data.stat_value_csv)
            sample_data = self._parse_sample_data(data.sample_info_csv)
            for meta in list(meta_lookup.keys()):
                for instance in list(meta_lookup[meta].keys()):
                    tags = {
                        "host": str(data.moref_name.lower()),
                        "location": str(data.location),
                        "type": str(data.moref_type),
                        "cluster": str(data.cluster),
                        "vcenter": str(vcenter),
                        "instance": str(instance),
                    }
                    json_data = []
                    for index in meta_lookup[meta][instance]:
                        _data = data.stat_value_csv[index]
                        json_data = self._format_json2(meta, _data, tags, sample_data, json_data)

                    json_series.append(json_data)

        return json_series

    def _format_json2(self, measurement, metric, tags, sample_data, json_series=[]):
        _json_series = []
        if not isinstance(tags, dict):
            raise TypeError("Parameter 'tags' expected type dict but recieved type '{}'".format(type(tags)))

        logger = LOGGERS.get_logger('Parser _format_json')
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

        return _json_series

    @staticmethod
    def _format_json(metric, sample_data, tags):
        json_series = []

        if not isinstance(tags, dict):
            raise TypeError("Parameter 'tags' expected type dict but received type '{}'".format(type(tags)))

        logger = LOGGERS.get_logger('Parser _format_json')
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

            # if metric.metric_name == 'cpu.usage.average':
            #     print(type(value))
            json_data = {
                'time': influx_time,
                'measurement': str(metric.metric_name),
                'fields': {
                    'metric_value': float(value)
                },
                'tags': tags,
            }
            json_series.append(json_data)

        return json_series

    @staticmethod
    def get_meta(metric_list):
        meta_lookup = {}
        index_track = 0

        for metric in metric_list:
            if meta_lookup.get(metric.metric_meta or None):
                # meta exists, store the index number
                if meta_lookup.get(metric.metric_meta).get(metric.metric_instance or None):
                    # entity instance exists, so update instance index
                    meta_lookup.get(metric.metric_meta).get(metric.metric_instance).append(index_track)
                else:
                    # metric meta exists but not instance
                    if metric.metric_instance is None or metric.metric_instance == '':
                        metric.metric_instance = 'all'
                    meta_lookup.get(metric.metric_meta).update({str(metric.metric_instance): [index_track]})
            else:
                # meta doesn't exist so have to create it
                if metric.metric_instance is None or metric.metric_instance == '':
                    metric.metric_instance = 'all'
                meta_lookup.update({metric.metric_meta: {str(metric.metric_instance): [index_track]}})

            index_track += 1

        return meta_lookup
