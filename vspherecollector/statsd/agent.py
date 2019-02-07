
import atexit
import logging
import queue
from datetime import datetime
from pyVmomi import vim, SoapAdapter
from vspherecollector.logger.handle import Logger
from vspherecollector.vmware.vcenter import Vcenter
from vspherecollector.args.handle import Args


LOGGERS = Logger(log_file='/var/log/vcenter_collector/statsd_agent.log',
                 error_log_file='/var/log/vcenter_collector/statsd_agent_err.log')


class QueryResult:

    class Metric:

        def __init__(self, metric, perfinfo):
            self.metric_id = metric.id.counterId
            self.metric_name = perfinfo.perf_counter_byId[metric.id.counterId].name
            self.metric_unit = perfinfo.perf_counter_byId[metric.id.counterId].unit
            self.metric_meta = self.metric_name.split('.')[0]
            if metric.id.instance is None or metric.id.instance == '':
                self.metric_instance = 'all'
            else:
                self.metric_instance = metric.id.instance
            self.metric_value_csv = metric.value

    def __init__(self, result, perfinfo, location, cluster):
        self.moref_name = result.entity.name
        self.moref_type = QueryResult._get_moref_type(result.entity)
        self.cluster = cluster
        self.location = location
        self.sample_info_csv = result.sampleInfoCSV
        self.stat_value_csv = [self.Metric(m, perfinfo) for m in result.value]
        self.stat_value_csv.sort(key=lambda x: x.metric_meta)

    @staticmethod
    def _get_moref_type(moref):
        """
        return a string for VM or HOST or CLUSTER based on the ManagedObject Type
        :param moref:
        :return:
        """

        if isinstance(moref, vim.VirtualMachine):
            return 'VM'
        elif isinstance(moref, vim.HostSystem):
            return 'HOST'
        elif isinstance(moref, vim.ClusterComputeResource):
            return 'CLUSTER'


class Statsd:

    def __init__(self, vcenter_list, in_q, out_q, tracker_q):
        logger = LOGGERS.get_logger('statsd_agent_initialization')
        self.in_q = in_q
        self.out_q = out_q
        self.tracker_q = tracker_q
        self.vc_refresh_trkr = {}
        self.vc_handles = {}
        args = Args()
        try:
            for vcenter in vcenter_list:
                logger.debug('Connecting to vCenter {}'.format(vcenter))
                vc = Vcenter(name=vcenter, username=args.username, _loggers=LOGGERS)
                vc.connect()
                self.vc_handles.update({vc.name: vc})
                self.vc_refresh_trkr.update({vc.name: datetime.now()})
                logger.debug('Register disconnect() for vcenter {} on atexit'.format(vcenter))
                atexit.register(self.vc_handles[vc.name].disconnect)

            logger.debug('launching statsd agent')
            self._run()
        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    def _run(self):

        logger = LOGGERS.get_logger('statsd_agent')
        logger.setLevel(logging.DEBUG)
        logger.info('statsd_agent started')
        queue_empty_flag = 1
        q_id = None
        try:
            while True:
                try:
                    # get the next item in the queue
                    data = self.in_q.get_nowait()
                    # logger.debug("Received Data from Queue : {}".format(data))
                    if data:
                        queue_empty_flag = 0
                        # from StatsCollector
                        #   data = [q_id, qSpecs, self.vcenter.name, dc_cl_map, self.perf_info]
                        q_id, serialized_qSpecs, vcenter, dc_cl_map, perf_info, ds_map = data
                        self._check_vc_refresh(vcenter)
                        logger.debug("Collecting stats on {} QuerySpecs".format(len(serialized_qSpecs)))
                        logger.debug("Deserialize qSpecs")
                        deserialized_specs = [SoapAdapter.Deserialize(spec) for spec in serialized_qSpecs.tolist()]
                        logger.debug("Deserialize perf_info object")
                        perf_info.deserialize()
                        logger.debug("perfManager.QueryStats on deserialized qSpecs")
                        query_results = self.vc_handles[vcenter].content.perfManager.QueryStats(querySpec=deserialized_specs)
                        logger.debug("Processed {} QueryStats".format(len(query_results)))

                        logger.debug('End Query of QuerySpecs')
                        logger.debug('Start Pickle Friendly object parse with {} results'.format(len(query_results)))
                        logger.debug("Sending {} Stats to Queue".format(len(query_results)))
                        logger.debug('query_results slice: {}'.format(query_results[0:2]))

                        for result in query_results:
                            # logger.debug(result)
                            logger.debug(result.entity._moId)
                            logger.debug(dc_cl_map[result.entity._moId]['cluster'])
                            logger.debug(dc_cl_map[result.entity._moId]['datacenter'])
                            out_dict = {
                                vcenter: {
                                    'cluster': dc_cl_map[result.entity._moId]['cluster'],
                                    'datacenter': dc_cl_map[result.entity._moId]['datacenter'],
                                    'ds_map': ds_map,
                                    'result': QueryResult(result,
                                                          perf_info,
                                                          dc_cl_map[result.entity._moId]['datacenter'],
                                                          dc_cl_map[result.entity._moId]['cluster'])
                                }
                             }
                            # logger.debug('Sending dict {} to queue'.format(out_dict))
                            self.out_q.put_nowait(out_dict)

                        logger.debug("Completed Sending {} Stats to Queue".format(len(query_results)))
                        logger.debug('End Pickle Friendly object parse')
                        self.tracker_q.put_nowait(q_id)

                except queue.Empty:
                    if queue_empty_flag == 0:
                        logger.debug("statsd agent complete")
                        queue_empty_flag = 1
                    # keep looping waiting for the queue not to be empty
                    pass
                except BaseException as e:
                    logger.debug("statsd agent SOMETHING WENT WRONG INSIDE LOOP!")
                    for vc in list(self.vc_handles.keys()):
                        self.vc_handles[vc].disconnect()
                    if q_id:
                        self.tracker_q.put_nowait(q_id)
                    logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
            logger.debug('Infinite loop has been broken')
        except BaseException as e:
            logger.debug("statsd agent SOMETHING WENT WRONG OUTSIDE LOOP!")
            for vc in list(self.vc_handles.keys()):
                self.vc_handles[vc].disconnect()
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    def _refresh_vcenter_connection(self, vcenter):
        logger = LOGGERS.get_logger('_refresh_vcenter_connection')
        try:
            self.vc_handles[vcenter].connect()
        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    def _check_vc_refresh(self, vcenter):
        logger = LOGGERS.get_logger('_check_vc_refresh')
        try:
            now = datetime.now()
            time_delta = now - self.vc_refresh_trkr[vcenter]
            logger.debug('Time Delta: {}'.format(time_delta.seconds))
            # every 5 minutes refresh the connection
            if time_delta.seconds >= 300:
                logger.debug('refreshing connection')
                self._refresh_vcenter_connection(vcenter)
                self.vc_refresh_trkr[vcenter] = datetime.now()
        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
