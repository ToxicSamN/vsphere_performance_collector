
import atexit
import logging
import queue
from datetime import datetime
from pyVmomi import vim, SoapAdapter
from vspherecollector.logger.handle import Logger
from vspherecollector.log.setup import addClassLogger
from vspherecollector.vmware.vcenter import Vcenter
from vspherecollector.args.handle import Args


# LOGGERS = Logger(log_file='/var/log/vcenter_collector/statsd_agent.log',
#                  error_log_file='/var/log/vcenter_collector/statsd_agent_err.log')


@addClassLogger
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
        elif isinstance(moref, vim.Datastore):
            return 'DATASTORE'


@addClassLogger
class Statsd:

    def __init__(self, vcenter_list, in_q, out_q, tracker_q):
        self.in_q = in_q
        self.out_q = out_q
        self.tracker_q = tracker_q
        self.vc_refresh_trkr = {}
        self.vc_handles = {}
        args = Args()
        try:
            for vcenter in vcenter_list:
                self.__log.debug(f'Connecting to vCenter {vcenter}')
                vc = Vcenter(name=vcenter, username=args.username)
                vc.connect()
                self.vc_handles.update({vc.name: vc})
                self.vc_refresh_trkr.update({vc.name: datetime.now()})
                self.__log.debug(f'Register disconnect() for vcenter {vcenter} on atexit')
                atexit.register(self.vc_handles[vc.name].disconnect)

            self.__log.debug('launching statsd agent')
            self._run()
        except BaseException as e:
            self.__log.exception(f'Exception: {e}, \n Args: {e.args}')

    def _run(self):

        self.__log.info('statsd_agent started')
        queue_empty_flag = 1
        q_id = None
        try:
            while True:
                try:
                    # get the next item in the queue
                    data = self.in_q.get_nowait()
                    # logger.debug(f"Received Data from Queue : {data}")
                    if data:
                        queue_empty_flag = 0
                        # from StatsCollector
                        #   data = [q_id, qSpecs, self.vcenter.name, dc_cl_map, self.perf_info]
                        q_id, serialized_qSpecs, vcenter, dc_cl_map, perf_info, ds_map = data
                        self._check_vc_refresh(vcenter)
                        self.__log.debug(f"Collecting stats on {len(serialized_qSpecs)} QuerySpecs")
                        self.__log.debug(f"Deserialize qSpecs")
                        deserialized_specs = [SoapAdapter.Deserialize(spec) for spec in serialized_qSpecs.tolist()]
                        self.__log.debug(f"Deserialize perf_info object")
                        perf_info.deserialize()
                        self.__log.debug(f"perfManager.QueryStats on deserialized qSpecs")
                        query_results = self.vc_handles[vcenter].content.perfManager.QueryStats(querySpec=deserialized_specs)
                        self.__log.debug(f"Processed {len(query_results)} QueryStats")

                        self.__log.debug(f'End Query of QuerySpecs')
                        self.__log.debug(f'Start Pickle Friendly object parse with {len(query_results)} results')
                        self.__log.debug(f"Sending {len(query_results)} Stats to Queue")
                        self.__log.debug(f'query_results slice: {query_results[0:2]}')

                        for result in query_results:
                            # logger.debug(result)
                            self.__log.debug(result.entity._moId)
                            self.__log.debug(dc_cl_map[result.entity._moId]['cluster'])
                            self.__log.debug(dc_cl_map[result.entity._moId]['datacenter'])
                            out_dict = {
                                vcenter: {
                                    'cluster': dc_cl_map[result.entity._moId]['cluster'],
                                    'datacenter': dc_cl_map[result.entity._moId]['datacenter'],
                                    'ds_map': ds_map,
                                    'inf.env': self.vc_handles[vcenter].env,
                                    'inf.role': self.vc_handles[vcenter].role,
                                    'inf.security': self.vc_handles[vcenter].security,
                                    'result': QueryResult(result,
                                                          perf_info,
                                                          dc_cl_map[result.entity._moId]['datacenter'],
                                                          dc_cl_map[result.entity._moId]['cluster'])
                                }
                             }
                            # logger.debug(f'Sending dict {out_dict} to queue')
                            self.out_q.put_nowait(out_dict)

                        self.__log.debug(f"Completed Sending {len(query_results)} Stats to Queue")
                        self.__log.debug(f'End Pickle Friendly object parse')

                        self.tracker_q.put_nowait(q_id)
                        self.__log.debug(
                            f'Q_ID: {q_id} placed in the tracker_q.')

                except queue.Empty:
                    if queue_empty_flag == 0:
                        self.__log.debug(f"statsd agent complete")
                        queue_empty_flag = 1
                    # keep looping waiting for the queue not to be empty
                    pass
                except BaseException as e:
                    self.__log.debug(f"statsd agent SOMETHING WENT WRONG INSIDE LOOP!")
                    for vc in list(self.vc_handles.keys()):
                        self.vc_handles[vc].disconnect()
                    if q_id:
                        self.tracker_q.put_nowait(q_id)

                    self.__log.exception(f'Exception: {e}, \n Args: {e.args}')

            self.__log.debug(f'Infinite loop has been broken')
        except BaseException as e:
            self.__log.debug(f"statsd agent SOMETHING WENT WRONG OUTSIDE LOOP!")
            for vc in list(self.vc_handles.keys()):
                self.vc_handles[vc].disconnect()

            self.__log.exception(f'Exception: {e}, \n Args: {e.args}')

    def _refresh_vcenter_connection(self, vcenter):

        try:
            self.vc_handles[vcenter].connect()
        except BaseException as e:
            self.__log.exception(f'Exception: {e}, \n Args: {e.args}')

    def _check_vc_refresh(self, vcenter):
        try:
            now = datetime.now()
            time_delta = now - self.vc_refresh_trkr[vcenter]
            self.__log.debug(f'Time Delta: {time_delta.seconds}')
            # every 5 minutes refresh the connection
            if time_delta.seconds >= 300:
                self.__log.debug(f'refreshing connection')
                self._refresh_vcenter_connection(vcenter)
                self.vc_refresh_trkr[vcenter] = datetime.now()
        except BaseException as e:
            self.__log.exception(f'Exception: {e}, \n Args: {e.args}')
