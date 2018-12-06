from datetime import datetime
from pyVmomi import vim
from multiprocessing.dummy import Pool as tPool
from multiprocessing.pool import Pool, MapResult, mapstar, RUN
from multiprocessing import cpu_count
from .logging import Logger


LOGGERS = Logger(log_file='/var/log/vcenter_stats.log', error_log_file='/var/log/vcenter_stats_err.log')


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
            raise ValueError("Pool not running")
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


class Perf:

    def __init__(self, name, key, unit):
        self.name = name
        self.key = key
        self.unit = unit


class PerfInfo(object):
    """ This will create a performance counter dict object """

    def __init__(self):
        self.perf_counter_byName = {}
        self.perf_counter_byId = {}
        self.counterIDs = []
        self.metricIDs = []

    def get_info(self, vcenter):
        # getting all of the available metrics from vCenter for ALL moRefs and store them in dictionaries for lookups
        perf_counter_list = vcenter.content.perfManager.perfCounter
        for counter in perf_counter_list:
            specific_counter = "{0}.{1}.{2}".format(counter.groupInfo.key,
                                                    counter.nameInfo.key,
                                                    counter.rollupType)
            self.update(Perf(name=specific_counter,
                             key=counter.key,
                             unit=counter.unitInfo.key
                             )
                        )

    def update(self, perf_obj):
        self.perf_counter_byName[perf_obj.name] = perf_obj
        self.perf_counter_byId[perf_obj.key] = perf_obj

    def get_counterIDs(self, vcenter, entity):
        for metric in vcenter.get_primary_metrics(entity):
            if not self.counterIDs.__contains__(self.perf_counter_byName[metric].key):
                self.counterIDs.append(self.perf_counter_byName[metric].key)

    def get_metricIDs(self):
        self.metricIDs = [vim.PerformanceManager.MetricId(counterId=c, instance="*") for c in self.counterIDs]


class QueryResult:

    class Metric:

        def __init__(self, metric, perfinfo):
            self.metric_id = metric.id.counterId
            self.metric_name = perfinfo.perf_counter_byId[metric.id.counterId].name
            self.metric_unit = perfinfo.perf_counter_byId[metric.id.counterId].unit
            self.metric_meta = self.metric_name.split('.')[0]
            self.metric_instance = metric.id.instance
            self.metric_value_csv = metric.value

    def __init__(self, result, perfinfo):
        self.moref_name = result.entity.name
        self.moref_type = QueryResult._get_moref_type(result.entity)
        self.cluster = (QueryResult._get_vm_cluster_from_obj(result.entity)).name
        self.location = (QueryResult._get_datacenter_from_obj(result.entity, self.moref_name)).name
        self.sample_info_csv = result.sampleInfoCSV
        self.stat_value_csv = [self.Metric(m, perfinfo) for m in result.value]
        self.stat_value_csv.sort(key=lambda x: x.metric_meta)

    @staticmethod
    def _get_datacenter_from_obj(obj, moref_name):
        """
        recursive function to crawl up the tree to find the datacenter
        :param obj:
        :return:
        """

        if not isinstance(obj, vim.Datacenter):
            if not hasattr(obj, 'parent'):
                return CustomObject({"name": "0319"})

            return QueryResult._get_datacenter_from_obj(obj.parent, moref_name)
        else:
            return obj

    @staticmethod
    def _get_vm_cluster_from_obj(obj):
        """
        Pass a VM object and this will return the cluster that object belongs to. this implies that the Vm is part of a cluster
        This will fail if the Vm is not in a cluster
        :param obj:
        :return:
        """

        if isinstance(obj, vim.VirtualMachine):
            return obj.resourcePool.owner
        elif isinstance(obj, vim.HostSystem):
            if isinstance(obj.parent, vim.ClusterComputeResource):
                return obj.parent
        elif isinstance(obj, vim.ClusterComputeresource):
            return obj
        elif isinstance(obj, vim.ResourcePool):
            return obj.owner

        return CustomObject({'name': 'NoCluster'})

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

        if float(vcenter.content.about.apiVersion) < 6.5:
            return 64
        else:
            return 256

    def create_querySpec(self, view):
        self.querySpecs.append(self.vcenter.get_QuerySpec(view, self.perf_info.metricIDs))

    def query_stats(self, statsq, managed_objects):
        """
            This method is used to define the devices and multiprocess pool size.
            It also formulates the function arguments that will be passed on to
            the payload process _query_stats via the protected method _query_thread_pool_map
        :param statsq: processing queue
        :return: None ( data is stored into statsq )
        """
        logger = LOGGERS.get_logger('statsd')
        logger.info('StatsCollector statsd started')
        # Define the number os parallel processes to run, typically the best results are cpu_count()
        # experiment with the sizing to determine the best number
        parallelism_thread_count = cpu_count()
        rawdata = []
        thread_pool_args = []
        query_results = []
        thread = 1

        try:
            self.perf_info.get_counterIDs(vcenter=self.vcenter,
                                          entity=managed_objects[0])
            self.perf_info.get_metricIDs()

            # define group sizes and start/end indexes for slicing
            for mo in managed_objects:
                self.create_querySpec(mo)
            print('{}, Start Query of QuerySpecs'.format(datetime.now()))
            qSpec_chunks = [qSpecs for qSpecs in
                            self.chunk_it(input_list=self.querySpecs,
                                          chunk_size=self.get_max_spec_size(self.vcenter))]
            for qSpecs in qSpec_chunks:
                query_results = query_results.__add__(self.vcenter.content.perfManager.QueryStats(querySpec=qSpecs))
            print('{}, End Query of QuerySpecs'.format(datetime.now()))
            print('{}, Start Pickle Friendly object parse'.format(datetime.now()))
            [statsq.put_nowait({self.vcenter.name: QueryResult(result, self.perf_info)}) for result in query_results]
            print('{}, End Pickle Friendly object parse'.format(datetime.now()))

        except BaseException as e:
            logger.error('Parralelism Count: {}, ThreadCount: {}, \n ThreadArgs: {}'.format(parallelism_thread_count, thread, thread_pool_args))
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    @staticmethod
    def _query_thread_pool_map(func_args_array, pool_size=2):
        """
        This is the multithreading function that maps _query_stats with func_args_array
        :param func_args_array: An array of arguments that will be passed along to _query_stats
                                This is similar to *args
        :param pool_size: Defines the number of parallel processes to be executed at once
        """
        # TODO ERROR HANDLING HERE
        logger = LOGGERS.get_logger('Process Mapping')
        try:
            logger.info('Mapping Processes')
            # Define the process pool size, or number of parallel processes
            p_pool = tPool(pool_size)
            #p_pool = CollectorProcessPool(pool_size)
            # map the function with the argument array
            #  Looks like this StatsCollector._query_stats(*args)
            # Once the mapping is done the process pool executes immediately
            p_pool.map(StatsCollector._query_stats, func_args_array)
        except BaseException as e:
            logger.error(
                'Parralelism Count: {} \n ThreadArgs: {}'.format(pool_size, func_args_array))
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    @staticmethod
    def _query_stats(thread_args):

        logger = LOGGERS.get_logger('_query_stats')
        try:
            vcenter, query_specs, thread_id, statsq, perfinfo = thread_args
            """ The payload processor. This method is what is called in the multiprocess pool
                to collect the stats. Once the stats have been collected they are stored into
                a statsq in which a background process churns through the queue parsing the
                data to send to influxdb.
            """
            logger.info('Query Performance Manager for {} QuerySpecs'.format(len(query_specs)))
            query_results = vcenter.content.perfManager.QueryStats(querySpec=query_specs)
            logger.info('Query Performance Manager Complete for {} QuerySpecs'.format(len(query_specs)))
            logger.info('Pickle Friendly List for {} QueryResults'.format(len(query_results)))
            [statsq.put_nowait({vcenter.name: QueryResult(result, perfinfo)}) for result in query_results]
            logger.info('Pickle Friendly List Complete for {} QueryResults'.format(len(query_results)))

        except BaseException as e:
            logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

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


