import sys, os, subprocess
import re
import platform
import uuid
import json
import requests
import logging
import logging.config
import logging.handlers
import time
import math
import threading
from influxdb import InfluxDBClient
from multiprocessing import Process as mp
from socket import gethostname
from datetime import datetime
from datetime import timedelta
from pyVmomi import vim
from pyVmomi import vmodl

loggers = {}

""" 
This script very specific to the vmcollector VMs being used to collect VM performance data.
 Each collector VM runs with 4 tasks each task handles a group of VMs. The goal is to be able to collect all VM stats
 with as granular sampling as possible, in which case for VMware is 20 second sample intervals.
"""


# This has been tested with the following versions of software:
#     * Python 3.5 64 bit
#     * pyVmomi 6.5
#     * influxdb 1.2.4-1
#


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


class InfluxDB(object):
    """ Creating an Object to hold other objects """

    def __init__(self, data, influxdb_client):
        self.data = data
        self.influxdb_client = influxdb_client
        self.time_precision = 'n'
        self.protocol = 'json'


class InfluxDBThread(threading.Thread):
    """
     Inheritence from threading.thread and override the run method
     This is used ro start a new thread for sending influx data
    """

    def __init__(self, influx_obj, thread_id, entity_name=''):
        threading.Thread.__init__(self)
        self.influx_object = influx_obj
        self.thread_id = thread_id
        self.entity_name = entity_name

    def run(self):
        logger = get_logger(str('InfluxDBThread_' + str(self.thread_id)))
        try:
            logger.info("Total Metrics Being Sent to InfluxDB for {}: {}".format(self.entity_name,
                                                                                 len(self.influx_object.data)))
            if len(self.influx_object.data) > 50000:
                for chunk in chunk_it(self.influx_object.data, chunk_size=1000):
                    self.influx_object.influxdb_client.write_points(chunk,
                                                                    time_precision=self.influx_object.time_precision,
                                                                    protocol=self.influx_object.protocol)

            else:
                self.influx_object.influxdb_client.write_points(self.influx_object.data,
                                                            time_precision=self.influx_object.time_precision,
                                                            protocol=self.influx_object.protocol)
        except BaseException as e:
            args = get_args()
            logger.error("Total Metrics Being Sent to InfluxDB for {}: {}".format(self.entity_name,
                                                                                  len(self.influx_object.data)))
            logger.exception('Exception: {}'.format(e))
            try:
                logger.info("TRY AGAIN for {}".format(self.entity_name))
                influx_client = InfluxDBClient(host=args['TelegrafIP'],  # args.TelegrafIP
                                               port=int(args['pPort']),  # 8186
                                               username='anonymous',
                                               password='anonymous',
                                               database='perf_stats',
                                               timeout=5,
                                               retries=3)
                c_count = 1
                for chunk in chunk_it(self.influx_object.data, chunk_size=1000):
                    try:
                        influx_client.write_points(chunk,
                                           time_precision=self.influx_object.time_precision,
                                           protocol=self.influx_object.protocol)
                        c_count += 1
                    except:
                        logger.exception('RETRY FAILED!!! {} Chunk {}'.format(self.entity_name, str(c_count)))
                        c_count += 1
                        pass

            except:
                logger.exception('RETRY FAILED!!! {}'.format(self.entity_name))


class Perf(object):
    """ This will create a performance counter dict object """

    objectType = ""
    perf_dict = {}

    def __init__(self, objectType, perf_dict):
        self.objectType = objectType
        self.perf_dict = perf_dict

    def new(objectType=None, perf_dict=None):
        perf = Perf(objectType, perf_dict)
        return {objectType: perf_dict}

    def add(self, objectType, perf_dict):
        if objectType in self.keys():
            self[objectType].update({objectType: perf_dict})
        else:
            self.update({objectType: perf_counter_dict})
        return self


class UcgCryptoKey(object):
    """
    This is a custom class for obtaining the crypto key for the credentials. It defaults to the git repo, however,
    a new crypto key should be created for each individual server at the time of RSA Key pair creation.
    This is obviously security by obscurity and not really secure. There isn't a solid way to do this that is 100%
    truly secure.
        TODO to make this better:
            Option 1: devise a setup in which the crypto key is encrypted with RSA Key-pair and stored in the api
              database. When requesting the crypto key from the api the api will use RSA key-pair to decrypt and
              re-encrypt to send back. This eliminates filesystems storage completely.
    """

    if platform.system() == 'Windows':
        file_path = "G:\\ucg_secure\\ucg_crypto"

    elif platform.system() == 'Linux':
        file_path = "/u01/git_repo/ucg_secure/ucg_crypto"

    def __init__(self, file_path=''):
        if file_path:
            self.file_path = file_path

        self.crypto_key = UcgEncryption().md5(self.file_path).ByteString
        self.file_path = None


class UcgCredential(object):
    """
    This class is used to create or get a credential set.
    new(): A clear text password is presented to new() and this
     will get encrypted and the encrypted password will be returned.
    get(): An encrypted password is passed as well as a private key and crypto path (md5 bytestring)
     and this wil return the clear test password. this is used for pyVmomi in which you have to pass a clear text
     password to the SmartConnect()
    """

    def __init__(self, credential_type):
        self.credential_type = credential_type
        self.PublickKey = None
        self.encrypted_password = None

    def new(self, public_key, clear_password):
        tmp = UcgEncryption()
        tmp.encrypt(clear_password, public_key)
        clear_password = None
        self.PublickKey = public_key
        self.encrypted_password = tmp.encrypted_message

    def get(self, private_key, encrypted_password, crypto_path=''):
        if crypto_path:
            secret_code = UcgCryptoKey(crypto_path).crypto_key
        else:
            secret_code = UcgCryptoKey().crypto_key

        tmp = UcgEncryption()
        tmp.decrypt(private_key, encrypted_password, secret_code=secret_code)

        return tmp.decrypted_message


class UcgEncryption(object):
    """
    This class does the heavy lifting of encrypting string, decrypting strings, generating RSA Key-pair, or pulling the
    MD5 hash of a file. There is a default secret_code, but shouldn't have to tell you ... never use the default outside
    of development.
    """

    def encrypt(self, privateData, publickey_file, output_file=None):
        from Crypto.PublicKey import RSA
        from Crypto.Random import get_random_bytes
        from Crypto.Cipher import AES, PKCS1_OAEP
        import base64

        if type(privateData) is str:
            privateData = privateData.encode("utf-8")

        pubkey = RSA.import_key(open(publickey_file, 'r').read())
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        encrypted_message = cipher_rsa.encrypt(privateData)

        setattr(self, 'encrypted_message', base64.b64encode(encrypted_message))

    def decrypt(self, private_key_file, encrypted_data, secret_code=None):
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import AES, PKCS1_OAEP
        import base64

        if secret_code:
            private_key = RSA.import_key(open(private_key_file, 'rb').read(), passphrase=secret_code)
        else:
            private_key = RSA.import_key(open(private_key_file, 'rb').read())

        encrypted_data = base64.b64decode(encrypted_data)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        privateData = cipher_rsa.decrypt(encrypted_data)

        setattr(self, 'decrypted_message', str(privateData, "utf-8"))
        chk = None
        try:
            chk = getattr(self, 'encrypted_message')
        except:
            chk = None
            pass

        if chk:
            delattr(self, 'encrypted_message')

    def generate_rsa_key_pair(self, public_file=None, private_file=None,
                              secret_code=b'N-6NZG\xff<\xddL\x85:\xc5\xc4\xa8n'):
        from Crypto.PublicKey import RSA

        key = RSA.generate(2048)

        private, public = key.exportKey(passphrase=secret_code, pkcs=8,
                                        protection="scryptAndAES128-CBC"), key.publickey().exportKey()

        with open(private_file, 'wb') as f:
            f.write(private)
            f.close
        with open(public_file, 'wb') as f:
            f.write(public)
            f.close

        setattr(self, 'PublicKey_file', public_file)
        setattr(self, 'PrivateKey_file', private_file)

    def get_rsa_public_key_from_private_key(self, file_path=None, encrypted_key=None,
                                            secret_code=b'N-6NZG\xff<\xddL\x85:\xc5\xc4\xa8n'):
        from Crypto.PublicKey import RSA

        if file_path:
            encrypted_key = open(file_path, 'rb').read()

        key = RSA.import_key(encrypted_key, passphrase=secret_code)

        setattr(self, 'PublicKey', key.publickey().exportKey())

    def md5(self, fname):
        import hashlib

        hash_md5 = hashlib.md5()

        with open(fname, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
            f.close()
        setattr(self, 'md5', CustomObject(property={'HexString': hash_md5.hexdigest(),
                                                    'ByteString': hash_md5.digest()
                                                    }
                                          )
                )
        return CustomObject(property={'HexString': hash_md5.hexdigest(),
                                      'ByteString': hash_md5.digest()
                                      }
                            )


def run_thread_pool(func_args_array, pool_size=2):
    """
    This is the multithreading function that maps get_stats with func_args_array
    :param func_args_array:
    :param pool_size:
    :return:
    """

    from multiprocessing.dummy import Pool
    t_pool = Pool(pool_size)
    results = t_pool.map(get_stats2, func_args_array)
    t_pool.close()
    t_pool.join()
    return results


def run_influxthread_pool(func_args_array, pool_size=2):
    """
    This is the multithreading function that maps get_stats with func_args_array
    :param func_args_array:
    :param pool_size:
    :return:
    """

    from multiprocessing.dummy import Pool
    t_pool = Pool(pool_size)
    results = t_pool.map(send_influx, func_args_array)
    t_pool.close()
    t_pool.join()
    return results


def send_influx(args):

    influx_series, influx_client, thread_id, entity_name = args

    logger = get_logger('send_influx{}:{}'.format(thread_id, entity_name))

    keep_running = True
    error_count = 0

    while keep_running:
        try:
            influx_client.write_points(influx_series,
                                       time_precision='n',
                                       protocol='json')
            keep_running = False
        except BaseException as e:
                if not influx_chunk_n_send(influx_series, influx_client, thread_id):
                    logger.exception('RETRY FAILED {}\t{}'.format(entity_name, e))
                keep_running = False


def influx_chunk_n_send(influx_series, influx_client, id=''):

    # recursive function to continuously try to send influx data

    #logger = get_logger('chunk-n-send')


    if len(influx_series) > 1:
        count = 0
        for chunk in chunk_it(influx_series, chunk_size=len(influx_series)/2):
            count += 1
            try:
                #logger.info('sending chunk {}:{}'.format(id, count))
                influx_client.write_points(chunk, time_precision='n', protocol='json')
            except:
                #logger.error('Try Again Chunk-n-Send {}:{}'.format(id, count))
                influx_chunk_n_send(chunk, influx_client, str(str(id)+':'+str(count)))
        return True
    else:
        try:
            #logger.info('Last try chunk {}:{}'.format(id, 1))
            influx_client.write_points(influx_series, time_precision='n', protocol='json')
            return True
        except:
            #logger.exception('Unable to send influx data {}'.format(influx_series))
            return False


def get_moref_type(moref):
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


def get_stats(args):
    """
    This is the brains of the operation.
    Pass an array of QuerySpec objects as query_spec_array and this will collect the performance stats.
    This is not collecting ALL stats (although it could), however, it is limiting the stats based on a list definition
     in get_primary_metrics()
    :param args:
    :return:
    """

    from dateutil import parser as timeparser

    global LOG_LEVEL

    query_spec_array, perf_counter_dict, content, vcenter, threadID, influxdb_client = args
    logger = get_logger('get_stats' + str(threadID))
    logger.setLevel(LOG_LEVEL)
    logger.info('Start get_stats')
    logger.debug('Args: {}'.format(args))

    influxdb_series = []
    vm_environment = vcenter

    # the performance stats come in every 20 seconds for realtime stats in VMware.
    # Query the performance manager for the actual performance stats based on the primary_metrics defined
    results = content.perfManager.QueryStats(querySpec=query_spec_array)
    logger.debug('QueryStats Results\n{}'.format(results))
    logger.info('Total QueryStats Results {}'.format(len(results)))

    stime = datetime.now()

    # Loop through the results and create the influxDB json\
    thread_id = 0
    all_threads = []
    mydict = {}
    for result in results:
        logger.info(
            'Results for {}'.format(result.entity.name))
        influxdb_series = []
        sample_info = []
        thread_id = thread_id + 1
        count = 0
        moref_name = result.entity.name
        moref_type = get_moref_type(result.entity)
        cluster = (get_vm_cluster_from_obj(result.entity)).name
        location = (get_datacenter_from_obj(result.entity, moref_name)).name
        logger.info(
            'Processing Results for {}: Type: {}, Cluster: {}, Location: {}'.format(moref_name, moref_type, cluster,
                                                                                    location))
        samplecsv = result.sampleInfoCSV.split(',')
        sample_info = [{'interval': samplecsv[index], 'timestamp': timeparser.parse(samplecsv[index + 1])} for index in
                       range(int(len(samplecsv))) if index % 2 == 0]

        logger.debug('SampleInfo: {}'.format(sample_info))

        for metric in result.value:
            index = 0
            metric_instance = metric.id.instance
            metric_lookup = perf_counter_dict[metric.id.counterId]
            metric_name = metric_lookup.name
            metric_unit = metric_lookup.unit

            logger.debug(
                'Processing {} metric {}: Instance {}: Values {}'.format(moref_name, metric_name, metric_instance,
                                                                         metric.value))

            metriccsv_split = metric.value.split(',')
            for val in metriccsv_split:
                json_time = sample_info[index][
                    'timestamp']  # .strftime('%Y-%m-%dT%H:%M:%S')  # use the sample time for the influxdb time
                stat_interval = float(sample_info[index]['interval'])

                if metric_name == "cpu.ready.summation":
                    # CPU Ready is calculated as time_in_ms / (sample_interval *1000) and then multiply by 100 to get %
                    percent_ready = (float(val) / (stat_interval * 1000)) * 100
                    value = float(percent_ready)
                    unit = 'percent'
                elif metric_unit == 'percent':
                    value = float(val) / 100
                    unit = 'percent'
                else:
                    if val == None or val == '':
                        value = 0
                    else:
                        value = float(val)
                    unit = metric_unit

                if metric_instance == None or metric_instance == '':
                    metric_instance = '0'

                json_values = {
                    "time": json_time,
                    "measurement": str(metric_name),
                    'fields': {'value': float(value), },
                    'tags': {
                        "host": str(moref_name.lower()),
                        "location": str(location),
                        "type": str(moref_type),
                        "cluster": str(cluster),
                        "vcenter": str(vm_environment),
                        "instance": str(metric_instance),
                        "interval": str(stat_interval),
                    },
                }
                influxdb_series.append(json_values)
                index += 1
        # if len(influxdb_series) > 50000:
        #     subthread = 1
        #     for chunk in chunk_it(influxdb_series, chunk_size=50000):
        #         influx = InfluxDB(chunk, influxdb_client)
        #         thread = InfluxDBThread(influx, thread_id=('get_stats' + str(threadID) + '.' + str(subthread)), entity_name=moref_name.lower())
        #
        #         all_threads.append(thread)
        #         thread.start()
        #         subthread += 1
        # else:
        influx = InfluxDB(influxdb_series, influxdb_client)
        thread = InfluxDBThread(influx, thread_id=('get_stats' + str(threadID)), entity_name=moref_name.lower())

        all_threads.append(thread)
        thread.start()

    for thread in all_threads:
        if thread.is_alive():
            thread.join()
    return influxdb_series


def get_stats2(args):
    """
    This is the brains of the operation.
    Pass an array of QuerySpec objects as query_spec_array and this will collect the performance stats.
    This is not collecting ALL stats (although it could), however, it is limiting the stats based on a list definition
     in get_primary_metrics()
    :param args:
    :return:
    """

    from dateutil import parser as timeparser

    global LOG_LEVEL

    results, perf_counter_dict, content, vcenter, threadID, influxdb_client = args
    logger = get_logger('get_stats' + str(threadID))
    logger.setLevel(LOG_LEVEL)
    logger.info('Start get_stats')
    logger.debug('Args: {}'.format(args))

    influxdb_series = []
    thread_args = []
    vm_environment = vcenter

    # the performance stats come in every 20 seconds for realtime stats in VMware.
    # Query the performance manager for the actual performance stats based on the primary_metrics defined
    #results = content.perfManager.QueryStats(querySpec=query_spec_array)
    logger.debug('QueryStats Results\n{}'.format(results))
    logger.info('Total QueryStats Results {}'.format(len(results)))

    stime = datetime.now()

    # Loop through the results and create the influxDB json\
    thread_id = 0
    all_threads = []
    mydict = {}
    for result in results:
        logger.info(
            'Results for {}'.format(result.entity.name))
        influxdb_series = []
        sample_info = []
        thread_id = thread_id + 1
        count = 0
        moref_name = result.entity.name
        moref_type = get_moref_type(result.entity)
        cluster = (get_vm_cluster_from_obj(result.entity)).name
        location = (get_datacenter_from_obj(result.entity, moref_name)).name
        logger.info(
            'Processing Results for {}: Type: {}, Cluster: {}, Location: {}'.format(moref_name, moref_type, cluster,
                                                                                   location))
        samplecsv = result.sampleInfoCSV.split(',')
        sample_info = [{'interval': samplecsv[index], 'timestamp': timeparser.parse(samplecsv[index + 1])} for index in
                       range(int(len(samplecsv))) if index % 2 == 0]

        #logger.debug('SampleInfo: {}'.format(sample_info))

        for metric in result.value:
            index = 0
            metric_instance = metric.id.instance
            metric_lookup = perf_counter_dict[metric.id.counterId]
            metric_name = metric_lookup.name
            metric_unit = metric_lookup.unit

            logger.debug(
                'Processing {} metric {}: Instance {}: Values {}'.format(moref_name, metric_name, metric_instance,
                                                                         metric.value))

            metriccsv_split = metric.value.split(',')
            for val in metriccsv_split:
                json_time = sample_info[index][
                    'timestamp']  # .strftime('%Y-%m-%dT%H:%M:%S')  # use the sample time for the influxdb time
                stat_interval = float(sample_info[index]['interval'])

                if metric_name == "cpu.ready.summation":
                    # CPU Ready is calculated as time_in_ms / (sample_interval *1000) and then multiply by 100 to get %
                    percent_ready = (float(val) / (stat_interval * 1000)) * 100
                    value = float(percent_ready)
                    unit = 'percent'
                elif metric_unit == 'percent':
                    value = float(val) / 100
                    unit = 'percent'
                else:
                    if val == None or val == '':
                        value = 0
                    else:
                        value = float(val)
                    unit = metric_unit

                if metric_instance == None or metric_instance == '':
                    metric_instance = '0'

                json_values = {
                    "time": json_time,
                    "measurement": str(metric_name),
                    'fields': {'value': float(value), },
                    'tags': {
                        "host": str(moref_name.lower()),
                        "location": str(location),
                        "type": str(moref_type),
                        "cluster": str(cluster),
                        "vcenter": str(vm_environment),
                        "instance": str(metric_instance),
                        "interval": str(stat_interval),
                    },
                }
                influxdb_series.append(json_values)
                index += 1

        # if len(influxdb_series) > 50000:
        #     subthread = 1
        #     for chunk in chunk_it(influxdb_series, chunk_size=50000):
        #         influx = InfluxDB(chunk, influxdb_client)
        #         thread = InfluxDBThread(influx, thread_id=('get_stats' + str(threadID) + '.' + str(subthread)), entity_name=moref_name.lower())
        #
        #         all_threads.append(thread)
        #         thread.start()
        #         subthread += 1
        # else:
        #influx = InfluxDB(influxdb_series, influxdb_client)
        #thread = InfluxDBThread(influx, thread_id=('get_stats' + str(threadID)), entity_name=moref_name.lower())
        thread_args.append([influxdb_series, influxdb_client, str(threadID), moref_name.lower()])

    #     all_threads.append(thread)
    #     thread.start()
    #
    # for thread in all_threads:
    #     if thread.is_alive():
    #         thread.join()
    # return influxdb_series
    run_influxthread_pool(thread_args, pool_size=100)


def get_QuerySpec(managed_object, metric_id_dict=None, get_sample=False):
    """
    This will return a QuerySpec based on the managed_object type provided.
    vim.HostSystem and vim.VirtualMachine both have realtime stats, however, vim.ClusterComputeResource only has daily.
    TODO: to make this more dynamic, could pass in the # of samples instead of hardcoded 15 (5 minutes)
    :param managed_object:
    :param metric_id_dict:
    :return:
    """
    vm_sample = 15
    host_sample = 15

    if isinstance(managed_object, vim.ClusterComputeResource):
        # Define QuerySpec for ClusterComputeResource
        #  ClusterComputeResource does not have realtime stats, only daily roll-ups
        return vim.PerformanceManager.QuerySpec(entity=managed_object,
                                                metricId=metric_id_dict[type(managed_object)],
                                                startTime=(datetime.now() + timedelta(days=-1)),
                                                endTime=datetime.now(),
                                                format='csv')
    elif isinstance(managed_object, vim.HostSystem) or managed_object is vim.HostSystem:
        # Define QuerySpec for HostSystem
        if get_sample:
            return host_sample
        return vim.PerformanceManager.QuerySpec(maxSample=host_sample,
                                                entity=managed_object,
                                                metricId=metric_id_dict[vim.HostSystem],
                                                intervalId=20,
                                                format='csv')
    elif isinstance(managed_object, vim.VirtualMachine) or managed_object is vim.VirtualMachine:
        # Define QuerySpec for VirtualMachine
        if get_sample:
            return vm_sample
        return vim.PerformanceManager.QuerySpec(maxSample=vm_sample,
                                                entity=managed_object,
                                                metricId=metric_id_dict[vim.VirtualMachine],
                                                intervalId=20,
                                                format='csv')
    else:
        return None


def get_datacenter_from_obj(obj, moref_name):
    """
    recursive function to crawl up the tree to find the datacenter
    :param obj:
    :return:
    """

    if not isinstance(obj, vim.Datacenter):
        try:
            tmp = obj.parent
        except:
            return CustomObject({"name": "0319"})

        return get_datacenter_from_obj(obj.parent, moref_name)
    else:
        return obj


def get_vm_cluster_from_obj(obj):
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


def get_container_view(content, view_type, search_root=None, filter_expression=None):
    """
    Custom container_view function that allows the option for a a filtered expression such as name == john_doe
    This is similar to the Where clause in powershell.
    This function does not handle multiple evaluations such as 'and/or'. This can only evaluate a single expression.
    :param content:
    :param view_type:
    :param search_root:
    :param filter_expression:
    :return:
    """

    def create_filter_spec(pc, obj_view, view_type, prop):
        """
        Creates a Property filter spec for each property in prop
        :param pc:
        :param obj_view:
        :param view_type:
        :param prop:
        :return:
        """

        objSpecs = []

        for obj in obj_view:
            objSpec = vmodl.query.PropertyCollector.ObjectSpec(obj=obj)
            objSpecs.append(objSpec)
        filterSpec = vmodl.query.PropertyCollector.FilterSpec()
        filterSpec.objectSet = objSpecs
        propSet = vmodl.query.PropertyCollector.PropertySpec(all=False)
        propSet.type = view_type[0]
        propSet.pathSet = prop
        filterSpec.propSet = [propSet]
        return filterSpec

    def filter_results(result, value, operator):
        """
        Evaluates the properties based on the operator and the value being searched for.
        This does not accept  multiple evaluations (and, or) such as prop1 == value1 and prop2 == value2
        :param result:
        :param value:
        :param operator:
        :return:
        """

        objs = []

        # value and operator are a list as a preparation for later being able to evaluate and, or statements as well
        #  so for now we will just reference the 0 index since only a single expression can be given at this time
        operator = operator[0]
        value = value[0]
        if operator == '==':
            for o in result:
                if o.propSet[0].val == value:
                    objs.append(o.obj)
            return objs
        elif operator == '!=':
            for o in result:
                if o.propSet[0].val != value:
                    objs.append(o.obj)
            return objs
        elif operator == '>':
            for o in result:
                if o.propSet[0].val > value:
                    objs.append(o.obj)
            return objs
        elif operator == '<':
            for o in result:
                if o.propSet[0].val < value:
                    objs.append(o.obj)
            return objs
        elif operator == '>=':
            for o in result:
                if o.propSet[0].val >= value:
                    objs.append(o.obj)
            return objs
        elif operator == '<=':
            for o in result:
                if o.propSet[0].val <= value:
                    objs.append(o.obj)
            return objs
        elif operator == '-like':
            regex_build = ".*"
            for v in value.split('*'):
                if v == '"' or v == "'":
                    regex_build = regex_build + ".*"
                else:
                    tmp = v.strip("'")
                    tmp = tmp.strip('"')
                    regex_build = regex_build + "(" + re.escape(tmp) + ").*"
            regex = re.compile(regex_build)
            for o in result:
                if regex.search(o.propSet[0].val):
                    objs.append(o.obj)
            return objs
        elif operator == '-notlike':
            regex_build = ".*"
            for v in value.split('*'):
                if v == '"' or v == "'":
                    regex_build = regex_build + ".*"
                else:
                    tmp = v.strip("'")
                    tmp = tmp.strip('"')
                    regex_build = regex_build + "(" + re.escape(tmp) + ").*"
            regex = re.compile(regex_build)
            for o in result:
                if not regex.search(o.propSet[0].val):
                    objs.append(o.obj)
            return objs
        else:
            return None

    def break_down_expression(expression):
        """
        Pass an expression to this function and retrieve 3 things,
        1. the property to be evaluated
        2. the value of the property to be evaluated
        3. the operand of the the expression
        :param expression:
        :return:
        """

        operators = ["==", "!=", ">", "<", ">=", "<=", "-like", "-notlike", "-contains", "-notcontains"]
        expression_obj = CustomObject()
        for op in operators:
            exp_split = None
            exp_split = expression.split(op)
            if type(exp_split) is list and len(exp_split) == 2:
                exp_obj = CustomObject(property={'prop': exp_split[0].strip(),
                                                 'operator': op,
                                                 'value': exp_split[1].strip()})
                # expression_obj.add_property(property={'exp': exp_obj})
                return [exp_obj]

    if not search_root:
        search_root = content.rootFolder

    view_reference = content.viewManager.CreateContainerView(container=search_root,
                                                             type=view_type,
                                                             recursive=True)
    view = view_reference.view
    view_reference.Destroy()

    if filter_expression:

        expression_obj = break_down_expression(filter_expression)

        property_collector = content.propertyCollector
        filter_spec = create_filter_spec(property_collector, view, view_type, [obj.prop for obj in expression_obj])
        property_collector_options = vmodl.query.PropertyCollector.RetrieveOptions()
        prop_results = property_collector.RetrievePropertiesEx([filter_spec], property_collector_options)
        totalProps = []
        totalProps += prop_results.objects
        # RetrievePropertiesEx will only retrieve a subset of properties. So need to use ContinueRetrievePropertiesEx
        while prop_results.token:
            prop_results = property_collector.ContinueRetrievePropertiesEx(token=prop_results.token)
            totalProps += prop_results.objects
        view_obj = filter_results(totalProps, value=[obj.value for obj in expression_obj],
                                  operator=[obj.operator for obj in expression_obj])
    else:
        view_obj = view

    return view_obj


def write_json(file_path, json_data):
    """
    Custom function to write to a json file
    :param file_path:
    :param json_data:
    :return:
    """
    logger = get_logger('write_json')

    try:
        logger.info('Opening JSON file {}'.format(file_path))
        with open(file_path, 'w') as write_file:
            logging.debug('Writing JSON data \n{}'.format(json_data))
            write_file.write(json.dumps(json_data))
            write_file.close()
        return True
    except Exception as e:
        logger.exception('Failed to open file {}'.format(file_path))
        raise


def write_lines(file_path, input_object):
    """
    Will write a list of strings or a single string to a file
    :param file_path:
    :param input_object:
    :return:
    """
    str_format = ''
    if isinstance(input_object, list):
        for i in input_object:
            str_format = str_format + '{}\n'
    elif isinstance(input_object, str):
        str_format = '{}\n'
        input_object = [input_object]

    try:
        with open(file_path, 'a') as f:
            f.writelines(str_format.format(*input_object))
            f.close()
        return 0
    except:
        return 1


def connect_vcenter(name, username=None, password=None, credential=None, ssl_context=None):
    """
    Custom vcenter connection function so that the credentials can be parsed out and return the ServiceInstance
    :param name:
    :param username:
    :param password:
    :param credential:
    :param ssl_context:
    :return:
    """

    import platform
    import atexit
    import ssl
    from pyVim import connect

    logger = get_logger('connect_vcenter')

    try:
        if not ssl_context:
            context = ssl._create_unverified_context()
            context.verify_mode = ssl.CERT_NONE

        logger.debug('Getting Credential Information')
        if credential and credential is dict:
            username = credential.get('username', None)
            password = credential.get('password', None)
        elif credential and not credential is dict:
            raise TypeError("Credential must be type <class 'dict'> not " + str(type(credential)))
        elif not password and not credential:
            logger.debug('No username or password provided. Will read from encrypted files')
            args = get_args()
            logger.debug('args: {}'.format(args))
            cred = UcgCredential('vCenter')
            if platform.system() == 'Windows':
                username = 'oppvmwre'
                password = cred.get(private_key=args['secdir'] + '\\privkey',
                                    encrypted_password=open(args['secdir'] + '\\secure', 'rb').read(),
                                    crypto_path=args['secdir'] + '\\crypto')
            elif platform.system() == 'Linux':
                username = 'oppvmwre'
                password = cred.get(private_key=args['secdir'] + '/privkey',
                                    encrypted_password=open(args['secdir'] + '/secure', 'rb').read(),
                                    crypto_path=args['secdir'] + '/crypto')
        logger.info('Conecting to vCenter {}'.format(name))
        logger.debug(
            'Connection Params: vCenter: {}, Username: {}, {}, SSL_Context: {}'.format(name, username, password,
                                                                                       ssl_context))
        si = connect.SmartConnect(host=name,
                                  user=username,
                                  pwd=password,
                                  sslContext=context
                                  )

        atexit.register(connect.Disconnect, si)
        logger.debug('ServiceInstance: {}'.format(si))

        return si
    except BaseException as e:
        logger.exception('Exception: {} \n Args: {}'.format(e, e.args))


def responseok(response):
    """
    Returns TRUE or FALSE based on if the api response from requests.Response() is a 200-207 code.
    :param response:
    :return:
    """

    ok_response_codes = (
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
    )

    if isinstance(response, requests.models.Response):
        if ok_response_codes.__contains__(response.status_code):  # response OK
            return True
        else:
            return False
    return False


def get_group_info(controller, uuid):
    """
    This will query the API the controller is hosting to parse out the group information
    :param controller:
    :param uuid:
    :return:
    """

    collector_url = str('http://' + controller + ':8080/api/collector/')
    group_url = str('http://' + controller + ':8080/api/group/' + uuid + '/')

    groupinfo = {'Group': None, 'TotalGroups': None}

    try:
        api_response = requests.get(group_url)
        if responseok(api_response):
            groupinfo['Group'] = api_response.json()['group']

        api_response = requests.get(collector_url)
        if responseok(api_response):
            groupinfo['TotalGroups'] = len(api_response.json())

    except:
        groupinfo = None
        pass

    return groupinfo


def get_primary_metrics(moref):
    """
    Provide a ManagedObject and this function returns the stats to gather for that moRef.
    If needing to change which metrics are being gathered, this is where that happens.
    :param moref:
    :return:
    """

    if isinstance(moref, vim.VirtualMachine):
        return ['cpu.usage.average',
                'cpu.ready.summation',
                'cpu.usagemhz.average',
                'mem.usage.average',
                'mem.overhead.average',
                'mem.swapinRate.average',
                'mem.swapoutRate.average',
                'mem.vmmemctl.average',
                'net.usage.average',
                'virtualDisk.write.average',
                'virtualDisk.read.average',
                'virtualDisk.totalReadLatency.average',
                'virtualDisk.totalWriteLatency.average',
                'virtualDisk.readOIO.latest',
                'virtualDisk.writeOIO.latest',
                'disk.maxTotalLatency.latest',
                'disk.usage.average',
                'sys.uptime.latest']
    elif isinstance(moref, vim.HostSystem):
        return ['cpu.coreUtilization.average',
                'cpu.latency.average',
                'cpu.ready.summation',
                'cpu.usage.average',
                'cpu.utilization.average',
                'datastore.datastoreIops.average',
                'datastore.datastoreMaxQueueDepth.latest',
                'datastore.datastoreReadIops.latest',
                'datastore.datastoreReadOIO.latest',
                'datastore.datastoreWriteIops.latest',
                'datastore.datastoreWriteOIO.latest',
                'datastore.read.average',
                'datastore.totalReadLatency.average',
                'datastore.totalWriteLatency.average',
                'datastore.write.average',
                'disk.busResets.summation',
                'disk.deviceReadLatency.average',
                'disk.deviceWriteLatency.average',
                'disk.maxQueueDepth.average',
                'disk.numberRead.summation',
                'disk.numberWrite.summation',
                'disk.queueReadLatency.average',
                'disk.queueWriteLatency.average',
                'disk.read.average',
                'disk.totalReadLatency.average',
                'disk.totalWriteLatency.average',
                'disk.usage.average',
                'mem.heap.average',
                'mem.heapfree.average',
                'mem.latency.average',
                'mem.overhead.average',
                'mem.reservedCapacity.average',
                'mem.shared.average',
                'mem.sharedcommon.average',
                'mem.state.latest',
                'mem.swapin.average',
                'mem.swapinRate.average',
                'mem.swapout.average',
                'mem.swapoutRate.average',
                'mem.swapused.average',
                'mem.sysUsage.average',
                'mem.totalCapacity.average',
                'mem.unreserved.average',
                'mem.usage.average',
                'mem.vmmemctl.average',
                'net.broadcastRx.summation',
                'net.broadcastTx.summation',
                'net.bytesRx.average',
                'net.bytesTx.average',
                'net.droppedRx.summation',
                'net.droppedTx.summation',
                'net.errorsRx.summation',
                'net.errorsTx.summation',
                'net.multicastRx.summation',
                'net.multicastTx.summation',
                'net.packetsRx.summation',
                'net.packetsTx.summation',
                'net.received.average',
                'net.unknownProtos.summation',
                'net.usage.average',
                'storageAdapter.commandsAveraged.average',
                'storageAdapter.numberReadAveraged.average',
                'storageAdapter.numberWriteAveraged.average',
                'storageAdapter.read.average',
                'storageAdapter.totalReadLatency.average',
                'storageAdapter.totalWriteLatency.average',
                'storageAdapter.write.average',
                'storagePath.commandsAveraged.average',
                'storagePath.numberReadAveraged.average',
                'storagePath.numberWriteAveraged.average',
                'storagePath.read.average',
                'storagePath.totalReadLatency.average',
                'storagePath.totalWriteLatency.average',
                'storagePath.write.average',
                'sys.uptime.latest']
    else:
        return None


def chunk_it(input_list, chunk_size=1):
    avg = len(input_list) / float(chunk_size)
    out = []
    last = 0.0
    while last < len(input_list):
        check_not_null = input_list[int(last):int(last + avg)]
        if check_not_null:
            out.append(check_not_null)
        last += avg
    return out


def get_args():
    """
    This function will parse out the config file sections to define various variables

    :return:
    """
    import argparse
    from configparser import ConfigParser
    global DEBUG_MODE
    global MOREF_TYPE
    global LOG_SIZE
    global LOG_DIR
    global MAX_KEEP

    # Retrieve and set script arguments for use throughout
    parser = argparse.ArgumentParser(description="Deploy a new VM Performance Collector VM.")
    parser.add_argument('-debug', '--debug',
                        required=False, action='store_true',
                        help='Used for Debug level information')
    parser.add_argument('-type', '--collector-type',
                        required=True, action='store',
                        help='identifies what moRef type to collect on (HOST, VM)')
    cmd_args = parser.parse_args()
    parser = ConfigParser()

    DEBUG_MODE = cmd_args.debug
    MOREF_TYPE = cmd_args.collector_type

    args = {}
    config_filepath = None
    if platform.system() == 'Windows':
        args.update({'platform': 'Windows'})
        if os.path.isfile('C:\\TEMP\\tmp\\metrics.conf'):
            config_filepath = 'C:\\TEMP\\tmp\\metrics.conf'
            strip_char = '\\'
        else:
            raise "Unable to locate config file /etc/metrics/metrics.conf"
    elif platform.system() == 'Linux':
        args.update({'platform': 'Linux'})
        if os.path.isfile('/etc/metrics/metrics.conf'):
            config_filepath = '/etc/metrics/metrics.conf'
            strip_char = '/'
        else:
            raise "Unable to locate config file /etc/metrics/metrics.conf"

    parser.read(config_filepath)

    # [GLOBAL]
    args.update({'bin': str(parser.get('global', 'WorkingDirectory')).rstrip(strip_char)})
    args.update({'tmpdir': str(parser.get('global', 'TempDirectory')).rstrip(strip_char)})
    args.update({'role': parser.get('global', 'ServerRole')})

    # [LOGGING]
    args.update({'logdir': str(parser.get('logging', 'LogDir')).rstrip(strip_char)})
    args.update({'logsize': parser.get('logging', 'LogRotateSizeMB')})
    args.update({'maxkeep': parser.get('logging', 'MaxFilesKeep')})
    args.update({'secdir': parser.get('global', 'SecureDir')})
    LOG_DIR = args['logdir']
    LOG_SIZE = args['logsize']
    MAX_KEEP = args['maxkeep']

    # [INFLUXDB]
    args.update({'TelegrafIP': parser.get('influxdb', 'TelegrafIP')})
    args.update({'npPort': parser.get('influxdb', 'nonprod_port')})
    args.update({'pPort': parser.get('influxdb', 'prod_port')})

    try:
        debug_check = parser.get('logging', 'Debug')
        if debug_check == 'True':
            DEBUG_MODE = True
    except:
        pass

        # [METRICS]
    args.update({'ControllerIP': parser.get('metrics', 'ControllerIP')})
    args.update({'vCenterIP': parser.get('metrics', 'vcenterIP')})
    args.update({'CollectorType': str(cmd_args.collector_type)})
    args.update({'username': parser.get('metrics', 'username')})
    args.update({'password': parser.get('metrics', 'password')})

    groupinfo = get_group_info(controller=args['ControllerIP'], uuid=gethostname().lower())
    if groupinfo:
        args.update(groupinfo)

    # This is being developed on a windows pc so this is a development parameter set
    # since there is no available API, it is not used in production on RHEL
    if platform.system() == 'Windows':
        args.update({'Group': 2, 'TotalGroups': 2})

    return args


def get_logger(name):
    """
    For logging purposes each function or thread will need a new logger to log to the appropriate file.
    This function will check the global dict variable loggers for a logger witht he name provided,
     if found then it will return that logger, otherwise it will create a new logger.
    Using this method instead of logging.config.dictConfig() so as to prevent duplicate logging
    Admittedly, this is a workaround instead of trying to figure out how to utilize the built-in dictConfig()
     method properly and not have duplicate log entires.
    The overhead for this below method is minimal and works.
    :param name:
    :return:
    """
    global DEBUG_MODE
    global MOREF_TYPE
    global LOG_LEVEL
    global LOG_SIZE
    global LOG_DIR
    global MAX_KEEP
    global PATH_SEPARATOR
    global loggers

    if platform.system() == 'Windows':
        PATH_SEPARATOR = '\\'
    else:
        PATH_SEPARATOR = '/'

    if DEBUG_MODE:
        LOG_LEVEL = logging.DEBUG
    else:
        LOG_LEVEL = logging.INFO

    if MOREF_TYPE == 'VM':
        file_prefix = 'vm_'
    elif MOREF_TYPE == 'HOST':
        file_prefix = 'esxi_'
    else:
        file_prefix = ''

    if loggers.get(name):
        return loggers.get(name)
    else:
        formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")

        logsize = int(LOG_SIZE) * 1048576

        logger = logging.getLogger(name)
        logger.setLevel(LOG_LEVEL)

        dfh = logging.StreamHandler(stream=sys.stdout)
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(formatter)

        lfh = logging.handlers.RotatingFileHandler(LOG_DIR + PATH_SEPARATOR + file_prefix + 'get_metrics.log',
                                                       mode='a',
                                                       maxBytes=int(logsize),
                                                       backupCount=int(MAX_KEEP),
                                                       encoding='utf8',
                                                       delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(formatter)

        efh = logging.handlers.RotatingFileHandler(LOG_DIR + PATH_SEPARATOR + file_prefix + 'get_metrics_error.log',
                                                       mode='a',
                                                       maxBytes=int(logsize),
                                                       backupCount=int(MAX_KEEP),
                                                       encoding='utf8',
                                                       delay=False)
        efh.setLevel(logging.ERROR)
        efh.setFormatter(formatter)

        logger.addHandler(lfh)
        logger.addHandler(efh)

        loggers.update({name: logger})

        return logger


def main():
    """
    This is the main worker. The dude abides!
    :return:
    """
    global LOG_LEVEL
    global PATH_SEPARATOR

    try:
        # This would be the Main program execution
        args = get_args()

        main_logger = get_logger('main')

        main_logger.info('Starting get_metrics.py:  ARGS: {}'.format(args))

        prod_influx_client = InfluxDBClient(host=args['TelegrafIP'],  # args.TelegrafIP
                                            port=int(args['pPort']),  # 8186
                                            username='anonymous',
                                            password='anonymous',
                                            database='perf_stats',
                                            timeout=5,
                                            retries=3)

        numServers = int(args['TotalGroups'])
        group = int(args['Group'])

        # DEBUG
        #numServers = 5
        #group = 4

        main_logger.debug('Connecting to vcenter: {}'.format(args['vCenterIP']))
        si = connect_vcenter(name=args['vCenterIP'],
                             username=args['username'],
                             password=args['password'])
        content = si.RetrieveContent()
        si.RetrieveContent()
        main_logger.debug('Connected to vCenter')

        main_logger.debug('Parse out vCenter name')
        # collect the vcenter name for use in the metric JSON
        vc_name = [hostnameUrl
                   for hostnameUrl in content.setting.setting
                   if hostnameUrl.key == 'VirtualCenter.FQDN'][0].value

        vcenter = (vc_name.strip('.nordstrom.net')).lower()
        main_logger.debug('vCenter name {}'.format(vcenter))

        start_time = datetime.now()  # grab the start time for use in the runtime collector JSON

        if args['CollectorType'] == 'VM':
            # collect all of the VMs that are powered on
            all_views = get_container_view(content, [vim.VirtualMachine],
                                           filter_expression='runtime.powerState == poweredOn')
        elif args['CollectorType'] == 'HOST':
            # collect all of the VMs that are powered on
            all_views = get_container_view(content, [vim.HostSystem])
        elif args['CollectorType'] == 'CLUSTER':
            # collect all of the VMs that are powered on
            all_views = get_container_view(content, [vim.ClusterComputeResource])
classs PerfInfo
        # getting all of the available metrics from vCenter for ALL moRefs and store them in dictionaries for lookups
        perf_counter_list = content.perfManager.perfCounter
        perf_counter_dict = Perf.new()
        perf_counter_dict_reverse = Perf.new()
        for counter in perf_counter_list:
            specific_counter = "{0}.{1}.{2}".format(counter.groupInfo.key,
                                                    counter.nameInfo.key,
                                                    counter.rollupType)
            perf_counter_dict[counter.key] = CustomObject(
                property={'name': specific_counter, 'unit': counter.unitInfo.key})
            perf_counter_dict_reverse[specific_counter] = CustomObject(property={'key': counter.key,
                                                                                 'unit': counter.unitInfo.key})

        perf_metric_bytype = {}
        # Query Available metrics for this VirtualMachine
        counterIDs = [m.counterId for m in content.perfManager.QueryAvailableMetric(entity=all_views[0])]

        # reduce the counterIDs down to just the metrics defined in primary_metrics
        for met in get_primary_metrics(all_views[0]):
            if not counterIDs.__contains__(perf_counter_dict_reverse[met].key):
                counterIDs.append(perf_counter_dict_reverse[met].key)

        # Pull the metricIDs for the counterIDs defined
        metricIDs = [vim.PerformanceManager.MetricId(counterId=c, instance="*") for c in counterIDs]
        # store the metric IDs in a dict for retrieval later
        if args['CollectorType'] == 'VM':
            perf_metric_bytype.update({vim.VirtualMachine: metricIDs})
        elif args['CollectorType'] == 'HOST':
            perf_metric_bytype.update({vim.HostSystem: metricIDs})
        elif args['CollectorType'] == 'CLUSTER':
            perf_metric_bytype.update({vim.ClusterComputeResource: metricIDs})
        main_logger.debug('Get the defined perf metrics: {}'.format(metricIDs))
End Class PerfInfo
        # define group sizes and start/end indexes for slicing
        if group == numServers:
            group_size = int(len(all_views) / numServers)
            start_index = ((group - 1) * group_size)
            end_index = (len(all_views) - 1)

        elif group > 1:
            group_size = int(len(all_views) / numServers)
            start_index = ((group - 1) * group_size)
            end_index = (start_index + group_size) - 1

        elif group == 1:
            group_size = int(len(all_views) / numServers)
            start_index = 0
            end_index = (start_index + group_size) - 1
        main_logger.info(
            'Group size: {}, Starting Index: {}, Ending Index: {}'.format(group_size, start_index, end_index))

        # create a new thread for each moref for multi threading capabilities.
        # Paralelism will be throttled based parallelism_thread_count.
        parallelism_thread_count = 100
        specArray = []
        # DEBUG
        #print(datetime.now().ctime())
        #for view in all_views:
        for view in all_views[start_index:end_index + 1]:
            specArray.append(get_QuerySpec(view, perf_metric_bytype))
        main_logger.debug('Query specs: {}'.format(specArray))
        main_logger.info('Total Query specs: {}'.format(len(specArray)))
        # DEBUG
        #print(datetime.now().ctime())
        results = content.perfManager.QueryStats(querySpec=specArray)
        #print(datetime.now().ctime())

        # define the threading group sizes. This will pair down the number of entities
        #  that will be collected per thread and allowing vcenter to multi-thread the queries
        thread_pool_args = []
        thread = 1

        for chunk in chunk_it(results, parallelism_thread_count):
            thread_pool_args.append(
                [chunk, perf_counter_dict, content, vcenter, thread, prod_influx_client])
            thread += 1
            # main_logger.info(
            #     'Thread Pool Arguments: [specArray[{}:{}], perf_counter_dict, content, vcenter'.format(
            #         specArray.index(chunk[0]),
            #         specArray.index(
            #             chunk[len(
            #                 chunk) - 1]) + 1))

        # thread_groupsize = int(math.ceil(len(specArray) / parallelism_thread_count))
        # main_logger.info('Thread Group Size: {}'.format(thread_groupsize))

        # for thread in range(1, parallelism_thread_count+1):
        #     # print('thread : ' + str(thread))
        #     if thread == parallelism_thread_count:
        #         start_index = ((thread - 1) * thread_groupsize)
        #         if start_index >= len(specArray):
        #             break
        #         end_index = len(specArray) -1
        #     elif thread > 1:
        #         start_index = ((thread - 1) * thread_groupsize)
        #         end_index = start_index + thread_groupsize -1
        #     elif thread == 1:
        #         start_index = 0
        #         end_index = start_index + thread_groupsize -1
        #
        #


        # DEBUG
        # thread_results = run_thread_pool(thread_pool_args[0:1], pool_size=parallelism_thread_count)

        # this is a custom thread throttling function. Could probably utilize ThreadPools but wanted to have a little
        # more control.
        thread_results = run_thread_pool(thread_pool_args, pool_size=len(thread_pool_args))
        main_logger.debug('Get_Stats results for all threads: {}'.format(thread_results))

        # We want the end time to calculate the runtime of gathering the VM stats. Exclude the influxDB POST timing
        end_time = datetime.now()
        # Wrap up the metrics and output timing to the tsk.return files
        time_delta = end_time - start_time
        main_logger.info('Total Runtime for multi-threaded get_stats: {}'.format(time_delta.total_seconds()))

        # # create a JSON data point for the runtime information of the entire task
        # if time_delta.seconds > 240:
        #     threshold_breached = 'True'
        # else:
        #     threshold_breached = 'False'
        #
        # json_date = datetime.utcnow()
        # json_values = {
        #     "time": json_date.strftime("%Y-%m-%dT%H:%M:%S"),
        #     "measurement": 'vmcollector.runtime',
        #     'fields': {'value': float(time_delta.seconds), },
        #     'tags': {
        #         "collector": str(gethostname().lower()),
        #         "task": '1',
        #         "vcenter": str(vcenter),
        #         "instance": str(group),
        #         "unit": 'seconds',
        #         "threshold": str(threshold_breached),
        #         "interval": str(10),
        #     },
        # }
        #
        # json_series = []
        # json_series += [json_values]
        #
        # prod_influx_client.write_points(json_series, time_precision='n', protocol='json')

        return 0
    except BaseException as e:
        main_logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))


if __name__ == '__main__':

    global LOG_LEVEL
    global PATH_SEPARATOR

    args = get_args()

    root_logger = get_logger(__name__)
    error_count = 0

    # This code will be ran from a systemd service
    # so this needs to be an infinite loop
    while True:
        try:
            start_main = True
            if start_main:
                if args['CollectorType'] == 'VM':
                    sample_size = get_QuerySpec(vim.VirtualMachine, get_sample=True)
                elif args['CollectorType'] == 'HOST':
                    sample_size = get_QuerySpec(vim.HostSystem, get_sample=True)
                sample_interval = (sample_size * 20) - 20  # 1 sample is 20 seconds

                start_main = False
                start_time = datetime.now()
                root_logger.info('Executing MAIN...')
                #main()
                print(datetime.now().ctime())
                p = mp(target=main)
                p.start()
                p.join(sample_interval)
                if p.is_alive():
                    p.terminate()
                    root_logger.error(
                        'MAIN program running too long. Start Time: {}, End Time: {}'.format(start_time.ctime(),
                                                                                             datetime.now().ctime()))
                    start_main = True

                root_logger.info('Execution Complete')
                end_time = datetime.now()

            # evaluate the timing to determine how long to sleep
            #  since pulling X minutes of perf data then should sleep
            #  sample interval time minus the execution time
            #  reduce that time by 20 seconds to allow for the initial connections at main start

            exec_time_delta = end_time - start_time
            sleep_time = int(sample_interval - exec_time_delta.seconds)
            if sleep_time >= 1:
                time.sleep(sleep_time)
            time.sleep(1)
            error_count = 0
        except BaseException as e:
            root_logger.exception('Exception: {} \n Args: {}'.format(e, e.args))
            start_main = True
            time.sleep(1)
            if error_count > 20:
                raise e
            else:
                error_count = error_count + 1
                pass
