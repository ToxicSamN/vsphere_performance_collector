import numpy
import math
import uuid
import queue
import logging
from timeit import timeit
from datetime import datetime
from pyVmomi import vim, SoapAdapter, vmodl
from multiprocessing.dummy import Pool as tPool
from multiprocessing.pool import Pool, MapResult, mapstar, RUN
from multiprocessing import cpu_count
from vspherecollector.logger.handle import Logger
from vspherecollector.log.setup import addClassLogger


logger = logging.getLogger(__name__)


# LOGGERS = Logger(log_file='/var/log/vcenter_collector/stats.log',
#                  error_log_file='/var/log/vcenter_collector/stats_err.log')

@addClassLogger
class CustomObject(object):
    """ Because I came from powershell I was really spoiled with New-Object PSObject
    So I created a class that acts similar in which I can add and remove properties.

     TODO:
    """

    def __init__(self, property={}):
        for k, v in property.items():
            setattr(self, k, v)

    def add_property(self, property):
        for k, v in property.items():
            setattr(self, k, v)

    def remove_property(self, property_name):
        delattr(self, property_name)


@addClassLogger
class CollectorProcessPool(Pool):
    """
        Strictly for debugging purposes. There is no other value here for this class.
    """

    def map(self, func, iterable, chunksize=None):
        return self._map_async(func, iterable, mapstar, chunksize).get()

    def _map_async(self, func, iterable, mapper, chunksize=None, callback=None,
            error_callback=None):
        '''
        Helper function to implement map, starmap and their async counterparts.
        '''
        if self._state != RUN:
            raise ValueError(f"Pool not running")
        if not hasattr(iterable, '__len__'):
            iterable = list(iterable)

        if chunksize is None:
            chunksize, extra = divmod(len(iterable), len(self._pool) * 4)
            if extra:
                chunksize += 1
        if len(iterable) == 0:
            chunksize = 0

        task_batches = Pool._get_tasks(func, iterable, chunksize)
        result = MapResult(self._cache, chunksize, len(iterable), callback,
                           error_callback=error_callback)
        self._taskqueue.put(
            (
                self._guarded_task_generation(result._job,
                                              mapper,
                                              task_batches),
                None
            )
        )
        return result


@addClassLogger
class Perf:

    def __init__(self, name, key, unit):
        self.name = name
        self.key = key
        self.unit = unit


@addClassLogger
class PerfInfo(object):
    """ This will create a performance counter dict object """

    def __init__(self):
        self.perf_counter_byName = {}
        self.perf_counter_byId = {}
        self.counterIDs = []
        self.metricIDs = []

    def get_info(self, vcenter):
        logger = logging.getLogger(f'{self.__log.name}.get_info')
        try:
            # getting all of the available metrics from vCenter for ALL moRefs and store them in dictionaries for lookups
            perf_counter_list = vcenter.content.perfManager.perfCounter
            for counter in perf_counter_list:
                specific_counter = f"{counter.groupInfo.key}.{counter.nameInfo.key}.{counter.rollupType}"
                self.update(Perf(name=specific_counter,
                                 key=counter.key,
                                 unit=counter.unitInfo.key
                                 )
                            )
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    def update(self, perf_obj):
        logger = logging.getLogger(f'{self.__log.name}.update')
        try:
            self.perf_counter_byName[perf_obj.name] = perf_obj
            self.perf_counter_byId[perf_obj.key] = perf_obj
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    def get_counterIDs(self, vcenter, entity):
        logger = logging.getLogger(f'{self.__log.name}.get_counterIDs')
        try:
            for metric in vcenter.get_primary_metrics(entity):
                if not self.counterIDs.__contains__(self.perf_counter_byName[metric].key):
                    self.counterIDs.append(self.perf_counter_byName[metric].key)
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    def get_metricIDs(self):
        logger = logging.getLogger(f'{self.__log.name}.get_metricIDs')
        try:
            self.metricIDs = [vim.PerformanceManager.MetricId(counterId=c, instance="*") for c in self.counterIDs]
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    def serialize(self):
        logger = logging.getLogger(f'{self.__log.name}.serialize')
        try:
            from pyVmomi import SoapAdapter
            self.metricIDs = [SoapAdapter.Serialize(mid) for mid in self.metricIDs]
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    def deserialize(self):
        logger = logging.getLogger(f'{self.__log.name}.deserialize')
        try:
            from pyVmomi import SoapAdapter
            self.metricIDs = [SoapAdapter.Deserialize(mid) for mid in self.metricIDs]
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')


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
class StatsCollector:
    """
        This class is used as a statistics collector of specific devices for the UCS.
        The class as a whole is designed to be run as a separate process via the method
        query_stats. A multiprocessing queue is required in order to share data between
        the processes. There is no output or stored property with the results and is only
        accessible from the queue.get() method.
    """
    def __init__(self, vcenter):
        self.vcenter = vcenter
        self.query_results = []
        self.querySpecs = []
        self.thread_results = None
        self.perf_info = PerfInfo()
        self.perf_info.get_info(vcenter)

    @staticmethod
    def get_max_spec_size(vcenter):
        vc_version = vcenter.content.about.apiVersion
        vc_version = f'{vc_version.split(".")[0]}.{vc_version.split(".")[1]}'
        if float(vc_version) < 6.5:
            return 63
        else:
            return 254

    def create_querySpec(self, view):
        logger = logging.getLogger(f'{self.__log.name}.create_querySpec')
        try:
            _qspec = self.vcenter.get_QuerySpec(view, self.perf_info.metricIDs)
            self.querySpecs.append(SoapAdapter.Serialize(_qspec))
            logger.debug(
                f"VM: {_qspec.entity.name}, Metrics: {[self.perf_info.perf_counter_byId[m.counterId].name for m in _qspec.metricId]}")
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    @staticmethod
    def _parse_entity_types(view_list):
        index = 0
        view_types = []
        view_index = []
        for view in view_list:
            if not type(view).__name__ in view_types:
                view_types.append(type(view).__name__)
                view_index.append(index)
            index += 1

        return view_index

    def query_stats(self, agentq, agenttrackq, view_list):
        """
            This method is used to define the devices and multiprocess pool size.
            It also formulates the function arguments that will be passed on to
            the payload process _query_stats via the protected method _query_thread_pool_map
        :param statsq: processing queue
        :return: None ( data is stored into statsq )
        """

        self.__log.info(f'StatsCollector statsd started')
        # Define the number os parallel processes to run, typically the best results are cpu_count()
        # experiment with the sizing to determine the best number
        parallelism_thread_count = cpu_count()
        rawdata = []
        thread_pool_args = []
        query_results = []
        thread = 1

        try:
            # view_list format  = [[managed_object, datacenter, cluster],..]
            self.perf_info.get_counterIDs(vcenter=self.vcenter,
                                          entity=view_list[0][0])
            self.perf_info.get_metricIDs()

            self.__log.info(f'Start query spec creation and mapping')
            q_id_tracker = {self.vcenter.name: {}}
            dc_cl_map = {}
            for mo in view_list:
                self.create_querySpec(mo[0])
                dc_cl_map.update({
                                    mo[0]._moId: {
                                        'datacenter': mo[1],
                                        'cluster': mo[2]
                                    }
                })
            all_ds = self.vcenter.get_container_view([vim.Datastore])
            ds_map = self.map_filtered_objs(self.vcenter, all_ds, vim.Datastore, ['name', 'info.url'])
            self.__log.info(f'Start Query of QuerySpecs')
            if type(view_list[0][0]).__name__ == 'vim.Datastore':
                array_size = len(self.querySpecs)
            elif len(self.querySpecs) >= self.get_max_spec_size(self.vcenter):
                array_size = math.ceil(len(self.querySpecs)/self.get_max_spec_size(self.vcenter))
            else:
                 array_size = 1
            self.__log.info(f'Splitting the querySpecs into equal sized chunks of {array_size}')
            qSpec_chunks = [qSpecs for qSpecs in numpy.array_split(self.querySpecs, array_size)]
            self.perf_info.serialize()
            for qSpecs in qSpec_chunks:
                # qSpecs is a numpy array
                q_id = uuid.uuid4()
                q_id_str = q_id.__str__()
                agentq.put_nowait([q_id_str, qSpecs, self.vcenter.name, dc_cl_map, self.perf_info, ds_map])
                q_id_tracker[self.vcenter.name].update({q_id_str: True})

            queue_empty_flag = 0
            while True:
                try:
                    data = agenttrackq.get_nowait()
                    if data:
                        queue_empty_flag = 0
                        if q_id_tracker[self.vcenter.name].get(data or None):
                            q_id_tracker[self.vcenter.name][data] = False
                            self.__log.debug(
                                f"Statsd agent completed for {self.vcenter.name} Q_ID: {data}  {q_id_tracker[self.vcenter.name][data]}")
                        else:
                            agenttrackq.put_nowait()

                        if True not in list(q_id_tracker[self.vcenter.name].values()):
                            self.__log.debug(
                                f"Collector Complete for {self.vcenter.name}. All queues have been processed")
                            break

                except queue.Empty:
                    if queue_empty_flag == 0:
                        waiting = [k for k, v in q_id_tracker[self.vcenter.name].items() if v]
                        if waiting:
                            self.__log.debug(
                                f'Queue Empty: {self.vcenter.name} Waiting for num Q_IDs: {len(waiting)}')
                            queue_empty_flag = 1
                    pass

        except BaseException as e:
            self.__log.error(
                f'Parralelism Count: {parallelism_thread_count}, ThreadCount: {thread}, \n ThreadArgs: {thread_pool_args}')
            self.__log.exception(f'Exception: {e}, \n Args: {e.args}')

    # @staticmethod
    # def _query_thread_pool_map(func_args_array, pool_size=2):
    #     """
    #     This is the multithreading function that maps _query_stats with func_args_array
    #     :param func_args_array: An array of arguments that will be passed along to _query_stats
    #                             This is similar to *args
    #     :param pool_size: Defines the number of parallel processes to be executed at once
    #     """
    #     # TODO ERROR HANDLING HERE
    #     logger = logging.getLogger(f'{__name__}.StatsCollector._query_thread_pool_map')
    #     try:
    #         logger.info(f'Mapping Processes')
    #         # Define the process pool size, or number of parallel processes
    #         p_pool = tPool(pool_size)
    #         # map the function with the argument array
    #         #  Looks like this StatsCollector._query_stats(*args)
    #         # Once the mapping is done the process pool executes immediately
    #         p_pool.map(StatsCollector._query_stats, func_args_array)
    #     except BaseException as e:
    #         logger.error(
    #             f'Parralelism Count: {pool_size} \n ThreadArgs: {func_args_array}')
    #         logger.exception(f'Exception: {e}, \n Args: {e.args}')

    # @staticmethod
    # def _query_stats(thread_args):
    #
    #     logger = logging.getLogger(f'{__name__}.StatsCollector._query_stats')
    #     try:
    #         vcenter, query_specs, thread_id, statsq, perfinfo = thread_args
    #         """ The payload processor. This method is what is called in the multiprocess pool
    #             to collect the stats. Once the stats have been collected they are stored into
    #             a statsq in which a background process churns through the queue parsing the
    #             data to send to influxdb.
    #         """
    #         logger.info(f'Query Performance Manager for {query_specs} QuerySpecs')
    #         query_results = vcenter.content.perfManager.QueryStats(querySpec=query_specs)
    #         logger.info(f'Query Performance Manager Complete for {len(query_specs)} QuerySpecs')
    #         logger.info(f'Pickle Friendly List for {len(query_results)} QueryResults')
    #         [statsq.put_nowait({vcenter.name: QueryResult(result, perfinfo)}) for result in query_results]
    #         logger.info(f'Pickle Friendly List Complete for {len(query_results)} QueryResults')
    #
    #     except BaseException as e:
    #         logger.exception(f'Exception: {e}, \n Args: {e.args}')

    @staticmethod
    def chunk_it(input_list, num_chunks=0, chunk_size=0):
        """ Chunk it method to slice a list into smaller chunks"""

        out = []
        last = 0.0
        if num_chunks > 0:
            avg = len(input_list) / float(num_chunks)
        elif chunk_size > 0:
            avg = chunk_size

        while last < len(input_list):
            check_not_null = input_list[int(last):int(last + avg)]
            if check_not_null:
                out.append(check_not_null)
            last += avg

        return out

    @staticmethod
    def create_filter_spec(pc, obj_view, view_type, prop):
        """
        Creates a Property filter spec for each property in prop
        :param pc:
        :param obj_view:
        :param view_type:
        :param prop:
        :return:
        """
        logger = logging.getLogger(f'{__name__}.StatsCollector.create_filter_spec')
        try:
            objSpecs = []

            for obj in obj_view:
                objSpec = vmodl.query.PropertyCollector.ObjectSpec(obj=obj)
                objSpecs.append(objSpec)
            filterSpec = vmodl.query.PropertyCollector.FilterSpec()
            filterSpec.objectSet = objSpecs
            propSet = vmodl.query.PropertyCollector.PropertySpec(all=False)
            propSet.type = view_type
            propSet.pathSet = prop
            filterSpec.propSet = [propSet]
            return filterSpec
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    @staticmethod
    def filter_props(vc, view, view_type, props):
        logger = logging.getLogger(f'{__name__}.StatsCollector.filter_props')
        try:
            property_collector = vc.content.propertyCollector
            filter_spec = StatsCollector.create_filter_spec(property_collector, view, view_type, props)
            property_collector_options = vmodl.query.PropertyCollector.RetrieveOptions()
            prop_results = property_collector.RetrievePropertiesEx([filter_spec], property_collector_options)
            totalProps = []
            totalProps += prop_results.objects
            # RetrievePropertiesEx will only retrieve a subset of properties.
            # So need to use ContinueRetrievePropertiesEx
            while prop_results.token:
                prop_results = property_collector.ContinueRetrievePropertiesEx(token=prop_results.token)
                totalProps += prop_results.objects

            return totalProps
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')

    @staticmethod
    def map_filtered_objs(vc, view_objs, view_type, props):
        logger = logging.getLogger(f'{__name__}.StatsCollector.map_filtered_obj')
        try:
            objs_dict = {}
            props = StatsCollector.filter_props(vc, view_objs, view_type, props)
            for o in props:
                for prop in o.propSet:
                    if prop.name == 'name':
                        name = prop.val
                    elif prop.name == 'info.url':
                        url = prop.val

                url_split = url.split('/')
                uuid = url_split[len(url_split) - 2]
                objs_dict.update({uuid: name})

            return objs_dict
        except BaseException as e:
            logger.exception(f'Exception: {e}, \n Args: {e.args}')
