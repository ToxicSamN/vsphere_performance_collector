
import queue
import logging
from vspherecollector.logger.handle import Logger
from vspherecollector.log.setup import addClassLogger
from influxdb import InfluxDBClient

# LOGGERS = Logger(log_file='/var/log/vcenter_collector/influx.log',
#                  error_log_file='/var/log/vcenter_collector/influx_err.log')


@addClassLogger
class InfluxDB:

    def __init__(self, influxq, host='127.0.0.1', port=8186, username='anonymous', password='anonymous',
                 database='perf_stats', timeout=5, retries=3):

        self.in_q = influxq
        self.__host = host
        self.__port = port
        self.__username = username
        self.__password = password
        self.__database = database
        self.__timeout = timeout
        self.__retries = retries
        self.client = self.__create_influx_client()

        try:
            self._run()
        except BaseException as e:
            self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    def __create_influx_client(self):
        return InfluxDBClient(host=self.__host,
                              port=self.__port,
                              username=self.__username,
                              password=self.__password,
                              database=self.__database,
                              timeout=self.__timeout,
                              retries=self.__retries
                              )

    def _run(self):

        self.__log.info('InfluxDB process Started')
        queue_empty_flag = 1
        while True:
            try:
                json_data = self.in_q.get_nowait()
                queue_empty_flag = 0
                if json_data:
                    self.__log.debug('Data received')
                    try:
                        if isinstance(json_data, list):
                            # logger.info('Sending {} stats'.format(len(json_data)))
                            # for d in json_data:
                            #     logger.info('{}'.format(type(d['fields']['value'])))
                            self.client.write_points(json_data,
                                                     time_precision='s',
                                                     protocol='json'
                                                     )
                        else:
                            self.client.write_points(points=[json_data],
                                                     time_precision='s',
                                                     protocol='json'
                                                     )
                    except BaseException as e:
                        # Writing to InfluxDB was unsuccessful. For now let's just try to resend
                        self.__log.error('Failed to Send influx data {}'.format(json_data))
                        self.__log.info('Retry Sending stats: {}'.format(json_data))
                        self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))
                        self.client.write_points(points=json_data,
                                                 time_precision='s',
                                                 protocol='json'
                                                 )
                        pass
            except queue.Empty:
                if queue_empty_flag == 0:
                    self.__log.info("Influx Complete")
                    queue_empty_flag = 1
                pass
            except BaseException as e:
                self.__log.exception('Exception: {}, \n Args: {}'.format(e, e.args))

        self.__log.info('InfluxDB process Stopped')
