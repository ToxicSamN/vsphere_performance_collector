VERSION = "1.6.3"

import sys, os, subprocess
import re
import platform
import uuid
import ssl
import argparse
import json
import requests
import logging
import logging.config
import logging.handlers
import time
import math
import threading
import atexit
from configparser import ConfigParser
from dateutil import parser as timeparser
from vmwarelogin.credential import Credential
from influxdb import InfluxDBClient
from multiprocessing import Process as mp
from socket import gethostname
from datetime import datetime
from datetime import timedelta
from pyVmomi import vim
from pyVmomi import vmodl
from pyVim import connect
from multiprocessing.dummy import Pool


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


class Args:
    """
    Args Class handles the cmdline arguments passed to the code
    Usage can be stored to a variable or called by Args().<property>
    """
    DEBUG = False
    MOREF_TYPE = ''
    LOG_DIR = ''
    LOG_SIZE = ''
    MAX_KEEP = ''

    def __init__(self):
        # Retrieve and set script arguments for use throughout
        parser = argparse.ArgumentParser(description="Deploy a new VM Performance Collector VM.")
        parser.add_argument('-debug', '--debug',
                            required=False, action='store_true',
                            help='Used for Debug level information')
        parser.add_argument('-type', '--collector-type',
                            required=True, action='store',
                            help='identifies what moRef type to collect on (HOST, VM)')
        parser.add_argument('-c', '--config-file', default='/etc/metrics/metrics.conf',
                            required=False, action='store',
                            help='identifies location of the config file')
        cmd_args = parser.parse_args()
        parser = ConfigParser()

        self.DEBUG = cmd_args.debug
        self.MOREF_TYPE = cmd_args.collector_type

        args = {}
        parser.read(cmd_args.config_file)

        # [GLOBAL]
        self.bin = str(parser.get('global', 'WorkingDirectory'))
        #args.update({'bin': str(parser.get('global', 'WorkingDirectory')).rstrip(strip_char)})
        self.tmpdir = str(parser.get('global', 'TempDirectory'))
        #args.update({'tmpdir': str(parser.get('global', 'TempDirectory')).rstrip(strip_char)})
        self.role = parser.get('global', 'ServerRole')
        #args.update({'role': parser.get('global', 'ServerRole')})

        # [LOGGING]
        self.LOG_DIR = str(parser.get('logging', 'LogDir'))
        #args.update({'logdir': str(parser.get('logging', 'LogDir')).rstrip(strip_char)})
        self.LOG_SIZE = parser.get('logging', 'LogRotateSizeMB')
        #args.update({'logsize': parser.get('logging', 'LogRotateSizeMB')})
        self.MAX_KEEP = parser.get('logging', 'MaxFilesKeep')
        #args.update({'maxkeep': parser.get('logging', 'MaxFilesKeep')})
        self.secdir = parser.get('global', 'SecureDir')
        #args.update({'secdir': parser.get('global', 'SecureDir')})
        #LOG_DIR = args['logdir']
        #LOG_SIZE = args['logsize']
        #MAX_KEEP = args['maxkeep']

        # [INFLUXDB]
        self.TelegrafIP = parser.get('influxdb', 'TelegrafIP')
        #args.update({'TelegrafIP': parser.get('influxdb', 'TelegrafIP')})
        self.nonprod_port = parser.get('influxdb', 'nonprod_port')
        #args.update({'npPort': parser.get('influxdb', 'nonprod_port')})
        self.prod_port = parser.get('influxdb', 'prod_port')
        #args.update({'pPort': parser.get('influxdb', 'prod_port')})

        try:
            debug_check = parser.get('logging', 'Debug')
            if debug_check == 'True':
                self.DEBUG_MODE = True
        except:
            pass

        # [METRICS]
        self.ControllerIP = parser.get('metrics', 'ControllerIP')
        #args.update({'ControllerIP': parser.get('metrics', 'ControllerIP')})
        self.vCenterIP = parser.get('metrics', 'vcenterIP')
        #args.update({'vCenterIP': parser.get('metrics', 'vcenterIP')})
        self.CollectorType = str(cmd_args.collector_type)
        #args.update({'CollectorType': str(cmd_args.collector_type)})
        self.username = parser.get('metrics', 'username')
        #args.update({'username': parser.get('metrics', 'username')})
        self.__password = parser.get('metrics', 'password')
        #args.update({'password': parser.get('metrics', 'password')})

        self.group_info = GroupInfo(controller=self.ControllerIP, uuid=gethostname().lower())
        self.group_info.get_info()
        # This is being developed on a windows pc so this is a development parameter set
        # since there is no available API, it is not used in production on RHEL
        if platform.system() == 'Windows':
            self.group_info.Group = 2
            self.group_info.TotalGroups = 6

    def get(self):
        return self.__password


class Logger:

    def __init__(self):

        global LOGGERS
        global LOG_LEVEL

        self.loggers = {}
        self.log_level = logging.INFO

        args = Args()

        if args.DEBUG:
            self.log_level = logging.DEBUG

        if args.MOREF_TYPE == 'VM':
            self.logfile = os.path.join(args.LOG_DIR, 'vm_get_metrics.log')
            self.err_logfile = os.path.join(args.LOG_DIR, 'vm_get_metrics_error.log')
        elif args.MOREF_TYPE == 'HOST':
            self.logfile = os.path.join(args.LOG_DIR, 'esxi_get_metrics.log')
            self.err_logfile = os.path.join(args.LOG_DIR, 'esxi_get_metrics_error.log')
        else:
            self.logfile = os.path.join(args.LOG_DIR, 'get_metrics.log')
            self.logfile = os.path.join(args.LOG_DIR, 'get_metrics_error.log')

        self.formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")
        self.logsize = int(args.LOG_SIZE) * 1048576
        self.max_logs = int(args.MAX_KEEP)

    def get_logger(self, name):

        if self.loggers.get(name):
            return self.loggers.get(name)


        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)

        dfh = logging.StreamHandler(stream=sys.stdout)
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(self.formatter)

        lfh = logging.handlers.RotatingFileHandler(self.logfile,
                                                   mode='a',
                                                   maxBytes=self.logsize,
                                                   backupCount=self.max_logs,
                                                   encoding='utf8',
                                                   delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(self.formatter)

        efh = logging.handlers.RotatingFileHandler(self.err_logfile,
                                                   mode='a',
                                                   maxBytes=self.logsize,
                                                   backupCount=self.max_logs,
                                                   encoding='utf8',
                                                   delay=False)
        efh.setLevel(logging.ERROR)
        efh.setFormatter(self.formatter)

        logger.addHandler(lfh)
        logger.addHandler(efh)

        self.loggers.update({name: logger})

        return logger


class GroupInfo:

    def __init__(self, controller, uuid):
        """
        This will query the API the controller is hosting to parse out the group information
        :param controller:
        :param uuid:
        :return:
        """

        self.collector_url = str('http://{}:8080/api/collector/'.format(controller))
        self.group_url = str('http://{}:8080/api/group/{}/'.format(controller,
                                                                   uuid))

        self.Group = None
        self.TotalGroups = None

    def get_info(self):
        try:
            api_response = requests.get(self.group_url)
            if self._responseok(api_response):
                self.Group = api_response.json()['group']

            api_response = requests.get(self.collector_url)
            if self._responseok(api_response):
                self.TotalGroups = len(api_response.json())
                #logger = LOGGERS.get_logger('main')
                #logger.info('TotalGroups: {}'.format(self.TotalGroups))
        except BaseException as e:
            pass
            #logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))

    @staticmethod
    def _responseok(response):
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


class Vcenter:
    """
    Vcenter class handles basic vcenter methods such as connect, disconnect, get_container_view, ect
    """
    def __init__(self, name, username=None, password=None, credential=None, ssl_context=None):
        self.si = None
        self.content = None
        self.cookies = None
        self.vcenter = name
        self.name = name
        self.username = username
        self.__password = password
        self.__credential = credential
        self.ssl_context = ssl_context

    def connect(self):
        """
        validate whether username/password were passed or whether a private key should be used

        logger lines have been commented out until logging is fully implemented
        :return:
        """
        # TODO: Ensure logging is setup properly to reinstate the logger lines
        logger = Logger().get_logger('connect_vcenter')

        try:
            # if no ssl_context has been provided then set this to unverified context
            if not self.ssl_context:
                self.ssl_context = ssl._create_unverified_context()
                self.ssl_context.verify_mode = ssl.CERT_NONE

            logger.debug('Getting Credential Information')
            if self.__credential and self.__credential is dict:
                self.username = self.__credential.get('username', None)
                self.__password = self.__credential.get('password', None)
            elif self.__credential and not self.__credential is dict:
                raise TypeError("Credential must be type <class 'dict'> not " + str(type(self.__credential)))
            elif not self.__password and not self.__credential:
                logger.debug('No username or password provided. Will read from encrypted files')
                args = Args()
                logger.debug('args: {}'.format(ARGS))
                cred = Credential('vCenter')
                # ToDo: change this to use a read-only username oppvfog01
                self.username = 'oppvmwre'
                self.__password = cred.get(private_key=os.path.join(ARGS.secdir, 'privkey'),
                                           encrypted_password=open(os.path.join(ARGS.secdir, 'secure'), 'rb').read(),
                                           crypto_path=os.path.join(ARGS.secdir, 'crypto')
                                           )
            logger.info('Conecting to vCenter {}'.format(self.vcenter))
            logger.debug(
                'Connection Params: vCenter: {}, Username: {}, {}, SSL_Context: {}'.format(self.vcenter,
                                                                                           self.username,
                                                                                           self.__password,
                                                                                           self.ssl_context))
            self.si = connect.SmartConnect(host=self.vcenter,
                                           user=self.username,
                                           pwd=self.__password,
                                           sslContext=self.ssl_context
                                      )

            atexit.register(connect.Disconnect, self.si)
            logger.debug('ServiceInstance: {}'.format(self.si))

            self.content = self.si.RetrieveContent()

            vc_name = [hostnameUrl
                       for hostnameUrl in self.content.setting.setting
                       if hostnameUrl.key == 'VirtualCenter.FQDN'][0].value

            self.name = (vc_name.strip('.nordstrom.net')).lower()

        except BaseException as e:
            print('Exception: {} \n Args: {}'.format(e, e.args))
            logger.exception('Exception: {} \n Args: {}'.format(e, e.args))

    def disconnect(self):
        connect.Disconnect(self.si)

    def get_container_view(self, view_type, search_root=None, filter_expression=None):
        """
        Custom container_view function that allows the option for a filtered expression such as name == john_doe
        This is similar to the Where clause in powershell, however, this is case sensative.
        This function does not handle multiple evaluations such as 'and/or'. This can only evaluate a single expression.
        :param view_type: MoRef type [vim.VirtualMachine] , [vim.HostSystem], [vim.ClusterComputeResource], ect
        :param search_root: ManagedObject to search from, by default this is rootFolder
        :param filter_expression: Only return results that match this expression
        :return: list of ManagedObjects
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
            class Expression:
                def __init__(self, property, operator, value):
                    self.prop = property
                    self.operator = operator
                    self.value = value


            operators = ["==", "!=", ">", "<", ">=", "<=", "-like", "-notlike", "-contains", "-notcontains"]

            for op in operators:
                exp_split = None
                exp_split = expression.split(op)
                if type(exp_split) is list and len(exp_split) == 2:
                    exp_obj = Expression(property=exp_split[0].strip(),
                                         operator=op,
                                         value=exp_split[1].strip()
                                         )
                    return [exp_obj]

        if not search_root:
            search_root = self.content.rootFolder

        view_reference = self.content.viewManager.CreateContainerView(container=search_root,
                                                                      type=view_type,
                                                                      recursive=True)
        view = view_reference.view
        view_reference.Destroy()

        if filter_expression:

            expression_obj = break_down_expression(filter_expression)

            property_collector = self.content.propertyCollector
            filter_spec = create_filter_spec(property_collector, view, view_type, [obj.prop for obj in expression_obj])
            property_collector_options = vmodl.query.PropertyCollector.RetrieveOptions()
            prop_results = property_collector.RetrievePropertiesEx([filter_spec], property_collector_options)
            totalProps = []
            totalProps += prop_results.objects
            # RetrievePropertiesEx will only retrieve a subset of properties.
            # So need to use ContinueRetrievePropertiesEx
            while prop_results.token:
                prop_results = property_collector.ContinueRetrievePropertiesEx(token=prop_results.token)
                totalProps += prop_results.objects
            view_obj = filter_results(totalProps, value=[obj.value for obj in expression_obj],
                                      operator=[obj.operator for obj in expression_obj])
        else:
            view_obj = view

        return view_obj

    def break_down_cookie(self, cookie):
        """ Breaks down vSphere SOAP cookie
        :param cookie: vSphere SOAP cookie
        :type cookie: str
        :return: Dictionary with cookie_name: cookie_value
        """
        cookie_a = cookie.split(';')
        cookie_name = cookie_a[0].split('=')[0]
        cookie_text = ' {0}; ${1}'.format(cookie_a[0].split('=')[1],
                                          cookie_a[1].lstrip())
        self.cookies = {cookie_name: cookie_text}

    @staticmethod
    def get_datacenter_from_obj(obj, moref_name):
        """
        recursive function to crawl up the tree to find the datacenter
        :param obj:
        :return:
        """

        if not isinstance(obj, vim.Datacenter):
            if not hasattr(obj, 'parent'):
                return CustomObject({"name": "0319"})

            return Vcenter.get_datacenter_from_obj(obj.parent, moref_name)
        else:
            return obj

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def get_QuerySpec(managed_object, metric_id=None, get_sample=False):
        """
        This will return a QuerySpec based on the managed_object type provided.
        vim.HostSystem and vim.VirtualMachine both have realtime stats, however, vim.ClusterComputeResource only has daily.
        TODO: to make this more dynamic, could pass in the # of samples instead of hardcoded 15 (5 minutes)
        :param managed_object:
        :param metric_id_dict:
        :return:
        """
        # TODO: Provide the sample sizes via config file
        vm_sample = 15
        host_sample = 15

        if isinstance(managed_object, vim.ClusterComputeResource):
            # Define QuerySpec for ClusterComputeResource
            #  ClusterComputeResource does not have realtime stats, only daily roll-ups
            return vim.PerformanceManager.QuerySpec(entity=managed_object,
                                                    metricId=metric_id,
                                                    startTime=(datetime.now() + timedelta(days=-1)),
                                                    endTime=datetime.now(),
                                                    format='csv')
        elif isinstance(managed_object, vim.HostSystem) or managed_object is vim.HostSystem:
            # Define QuerySpec for HostSystem
            if get_sample:
                return host_sample
            return vim.PerformanceManager.QuerySpec(maxSample=host_sample,
                                                    entity=managed_object,
                                                    metricId=metric_id,
                                                    intervalId=20,
                                                    format='csv')
        elif isinstance(managed_object, vim.VirtualMachine) or managed_object is vim.VirtualMachine:
            # Define QuerySpec for VirtualMachine
            if get_sample:
                return vm_sample
            return vim.PerformanceManager.QuerySpec(maxSample=vm_sample,
                                                    entity=managed_object,
                                                    metricId=metric_id,
                                                    intervalId=20,
                                                    format='csv')
        else:
            return None

    @staticmethod
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


class Stats:
    def __init__(self, vcenter):
        self.vcenter = vcenter
        self.querySpec = []
        self.query_results = None
        self.thread_results = None

    def create_querySpec(self, view):
        self.querySpec.append(self.vcenter.get_QuerySpec(view, PERFINFO.metricIDs))

    def query_stats(self):
        self.query_results = self.vcenter.content.perfManager.QueryStats(querySpec=self.querySpec)

    def parse_results(self, influxdb_client, parallelism_thread_count=2):

        # create thread pool args and launch _run_thread_pool
        # define the threading group sizes. This will pair down the number of entities
        #  that will be collected per thread and allowing vcenter to multi-thread the queries
        thread_pool_args = []
        thread = 1

        for chunk in InfluxDBThread.chunk_it(self.query_results, parallelism_thread_count):
            # for chunk in chunk_it(specArray, parallelism_thread_count):
            thread_pool_args.append(
                [chunk, self.vcenter, thread, influxdb_client])
            thread += 1

        # this is a custom thread throttling function. Could probably utilize ThreadPools but wanted to have a little
        # more control.
        self.thread_results = self._run_thread_pool(thread_pool_args,
                                               pool_size=parallelism_thread_count)

    @staticmethod
    def _run_thread_pool(func_args_array, pool_size=2):
        """
        This is the multithreading function that maps get_stats with func_args_array
        :param func_args_array:
        :param pool_size:
        :return:
        """

        t_pool = Pool(pool_size)
        results = t_pool.map(Stats._parse_stats, func_args_array)
        t_pool.close()
        t_pool.join()
        return results

    @staticmethod
    def _parse_stats(thread_args):
        """
            This is the brains of the operation.
            Pass an array of QuerySpec objects as query_spec_array and this will collect the performance stats.
            This is not collecting ALL stats (although it could), however, it is limiting the stats based on a list definition
             in get_primary_metrics()
            :param args:
            :return:
            """

        results, vcenter, threadID, influxdb_client = thread_args
        logger = LOGGERS.get_logger('parse_stats' + str(threadID))
        logger.setLevel(LOGGERS.log_level)
        logger.info('Start parse_stats')
        logger.debug('Args: {}'.format(thread_args))

        influxdb_series = []

        logger.debug('QueryStats Results\n{}'.format(results))
        logger.info('Total QueryStats Results {}'.format(len(results)))

        # Loop through the results and create the influxDB json\
        thread_id = 0
        all_threads = []

        for result in results:
            logger.info(
                'Results for {}'.format(result.entity.name))
            influxdb_series = []
            thread_id = thread_id + 1

            moref_name = result.entity.name
            moref_type = Vcenter.get_moref_type(result.entity)
            cluster = (Vcenter.get_vm_cluster_from_obj(result.entity)).name
            location = (Vcenter.get_datacenter_from_obj(result.entity, moref_name)).name
            logger.info(
                'Processing Results for {}: Type: {}, Cluster: {}, Location: {}'.format(moref_name, moref_type, cluster,
                                                                                        location))
            samplecsv = result.sampleInfoCSV.split(',')
            sample_info = [{'interval': samplecsv[index], 'timestamp': timeparser.parse(samplecsv[index + 1])} for index
                           in
                           range(int(len(samplecsv))) if index % 2 == 0]

            logger.debug('SampleInfo: {}'.format(sample_info))

            for metric in result.value:
                index = 0
                metric_instance = metric.id.instance
                metric_lookup = PERFINFO.perf_counter_byId[metric.id.counterId]
                metric_name = metric_lookup.name
                metric_unit = metric_lookup.unit

                logger.debug(
                    'Processing {} metric {}: Instance {}: Values {}'.format(moref_name, metric_name, metric_instance,
                                                                             metric.value))

                metriccsv_split = metric.value.split(',')
                for val in metriccsv_split:
                    # use the sample time for the influxdb time
                    json_time = sample_info[index][
                        'timestamp']
                    stat_interval = float(sample_info[index]['interval'])

                    if metric_name == "cpu.ready.summation":
                        # CPU Ready is calculated as
                        # time_in_ms / (sample_interval *1000) and then multiply by 100 to get %
                        # this may be incorrect. It appears VMware adds all of the ms values for every vCPU
                        # to calculate overall %CPU_RDY
                        percent_ready = (float(val) / (stat_interval * 1000)) * 100
                        value = float(percent_ready)
                        unit = 'percent'
                    elif metric_unit == 'percent':
                        value = float(val) / 100
                        unit = 'percent'
                    else:
                        if val is None or val == '':
                            value = 0
                        else:
                            value = float(val)
                        unit = metric_unit

                    if metric_instance is None or metric_instance == '':
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
                            "vcenter": str(vcenter.name),
                            "instance": str(metric_instance),
                            "interval": str(stat_interval),
                        },
                    }
                    influxdb_series.append(json_values)
                    index += 1

            influx = InfluxDB(influxdb_series, influxdb_client)
            thread = InfluxDBThread(influx, thread_id=('parse_stats' + str(threadID)), entity_name=moref_name.lower())

            all_threads.append(thread)
            thread.start()

        for thread in all_threads:
            if thread.is_alive():
                thread.join()
        return influxdb_series


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
        logger = LOGGERS.get_logger(str('InfluxDBThread'))
        try:
            logger.info("{}: Total Metrics Being Sent to InfluxDB for {}: {}".format(str(self.thread_id),
                                                                                     self.entity_name,
                                                                                     len(self.influx_object.data)))

            InfluxDBThread.send_influx((self.influx_object.data,
                                        self.influx_object.influxdb_client,
                                        self.thread_id,
                                        self.entity_name))

        except BaseException as e:
            logger.error("{}: Total Metrics Being Sent to InfluxDB for {}: {}".format(str(self.thread_id),
                                                                                      self.entity_name,
                                                                                      len(self.influx_object.data)))
            logger.exception('{}: Exception: {}'.format(str(self.thread_id), e))
            try:
                logger.info("TRY AGAIN for {}: {}".format(self.entity_name, str(self.thread_id)))
                influx_client = InfluxDBClient(host=ARGS.TelegrafIP,  # args.TelegrafIP
                                               port=int(ARGS.prod_port),  # 8186
                                               username='anonymous',
                                               password='anonymous',
                                               database='perf_stats',
                                               timeout=5,
                                               retries=3)
                c_count = 1
                for chunk in InfluxDBThread.chunk_it(self.influx_object.data, chunk_size=1000):
                    try:
                        influx_client.write_points(chunk,
                                                   time_precision=self.influx_object.time_precision,
                                                   protocol=self.influx_object.protocol)
                        c_count += 1
                    except:
                        logger.exception('RETRY FAILED!!! {} Chunk {}: {}'.format(self.entity_name,
                                                                                  str(c_count),
                                                                                  str(self.thread_id)))
                        c_count += 1
                        pass

            except:
                logger.exception('RETRY FAILED!!! {}: {}'.format(self.entity_name,
                                                                 str(self.thread_id)))

    @staticmethod
    def send_influx(args):

        influx_series, influx_client, thread_id, entity_name = args

        logger = LOGGERS.get_logger('send_influx')

        keep_running = True
        while keep_running:
            try:
                influx_client.write_points(influx_series,
                                           time_precision='n',
                                           protocol='json')
                keep_running = False
            except BaseException as e:
                if not InfluxDBThread.influx_chunk_n_send(influx_series, influx_client, thread_id):
                    logger.exception('RETRY FAILED {}\t{}'.format(entity_name, e))
                break

    @staticmethod
    def influx_chunk_n_send(influx_series, influx_client, id=''):

        if len(influx_series) > 1:
            count = 0
            for chunk in InfluxDBThread.chunk_it(influx_series, chunk_size=(len(influx_series) / 2)):
                count += 1
                try:
                    # logger.info('sending chunk {}:{}'.format(id, count))
                    influx_client.write_points(chunk, time_precision='n', protocol='json')
                except:
                    # logger.error('Try Again Chunk-n-Send {}:{}'.format(id, count))
                    InfluxDBThread.influx_chunk_n_send(chunk, influx_client, str(str(id) + ':' + str(count)))
            return True
        else:
            try:
                # logger.info('Last try chunk {}:{}'.format(id, 1))
                influx_client.write_points(influx_series, time_precision='n', protocol='json')
                return True
            except:
                # logger.exception('Unable to send influx data {}'.format(influx_series))
                return False

    @staticmethod
    def chunk_it(input_list, chunk_size=1.0):
        avg = len(input_list) / float(chunk_size)
        out = []
        last = 0.0
        while last < len(input_list):
            check_not_null = input_list[int(last):int(last + avg)]
            if check_not_null:
                out.append(check_not_null)
            last += avg
        return out


def main():
    """
    This is the main worker. The dude abides!
    :return:
    """

    try:
        # This would be the Main program execution
        si = None

        main_logger = LOGGERS.get_logger('main')
        main_logger.info('Starting get_metrics.py:  ARGS: {}\nGroupInfo:  {}'.format(ARGS.__dict__,
                                                                                     ARGS.group_info.__dict__))

        group = int(ARGS.group_info.Group)
        numServers = int(ARGS.group_info.TotalGroups)

        main_logger.debug('Connecting to vcenter: {}'.format(ARGS.vCenterIP))
        vcenter = Vcenter(name=ARGS.vCenterIP,
                          username=ARGS.username,
                          password=ARGS.get())
        vcenter.connect()
        main_logger.debug('Connected to vCenter')
        main_logger.debug('vCenter name {}'.format(vcenter.name))

        start_time = datetime.now()  # grab the start time for use in the runtime collector JSON


        if ARGS.MOREF_TYPE == 'VM':
            # collect all of the VMs that are powered on
            all_views = vcenter.get_container_view([vim.VirtualMachine],
                                                   filter_expression='runtime.powerState == poweredOn')
        elif ARGS.MOREF_TYPE == 'HOST':
            # collect all of the VMHosts
            all_views = vcenter.get_container_view([vim.HostSystem])
        else:
            raise ValueError("Unable to determine MOREF_TYPE of {} when Expecting VM or HOST".format(ARGS.MOREF_TYPE))

        PERFINFO.get_info(vcenter)
        PERFINFO.get_counterIDs(vcenter=vcenter,
                                entity=all_views[0])
        PERFINFO.get_metricIDs()
        main_logger.debug('Get the defined perf metrics: {}'.format(PERFINFO.metricIDs))

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

        # initialize the Stats service
        statsd = Stats(vcenter)
        for view in all_views[start_index:end_index + 1]:
            statsd.create_querySpec(view)

        main_logger.debug('Query specs: {}'.format(statsd.querySpec))
        main_logger.info('Total Query specs: {}'.format(len(statsd.querySpec)))

        statsd.query_stats()

        prod_influx_client = InfluxDBClient(host=ARGS.TelegrafIP,  # ARGS.TelegrafIP
                                            port=int(ARGS.prod_port),  # 8186
                                            username='anonymous',
                                            password='anonymous',
                                            database='perf_stats',
                                            timeout=5,
                                            retries=3)

        statsd.parse_results(influxdb_client=prod_influx_client,
                             parallelism_thread_count=50)

        main_logger.debug('Parse_Stats results for all threads: {}'.format(statsd.thread_results))

        # We want the end time to calculate the runtime of gathering the VM stats. Exclude the influxDB POST timing
        end_time = datetime.now()
        # Wrap up the metrics and output timing to the tsk.return files
        time_delta = end_time - start_time
        main_logger.info('Total Runtime for multi-threaded parse_stats: {}'.format(time_delta.total_seconds()))

        vcenter.disconnect()

        return 0
    except BaseException as e:
        if si:
            connect.Disconnect(si)
        main_logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))


if __name__ == '__main__':

    global ARGS
    global LOGGERS
    global PERFINFO
    ARGS = Args()
    LOGGERS = Logger()
    PERFINFO = PerfInfo()

    root_logger = LOGGERS.get_logger(__name__)
    root_logger.info('Code Version : {}'.format(VERSION))
    error_count = 0

    if ARGS.MOREF_TYPE == 'VM':
        sample_size = Vcenter.get_QuerySpec(vim.VirtualMachine, get_sample=True)
    elif ARGS.MOREF_TYPE == 'HOST':
        sample_size = Vcenter.get_QuerySpec(vim.HostSystem, get_sample=True)
    sample_interval = (sample_size * 20) - 5  # 1 sample is 20 seconds

    # This code will be ran from a systemd service
    # so this needs to be an infinite loop
    while True:
        try:
            with open(os.path.realpath(__file__), 'r') as f:
                line = f.readline()
                f.close()
            code_version = line.split("=")[1].replace('\"', '').strip('\n').strip()
            if not code_version == VERSION:
                logging.exception("Code Version change from current version {} to new version {}".format(VERSION,
                                                                                                         code_version))
                sys.exit(-1)

            start_main = True
            if start_main:
                start_main = False
                start_time = datetime.now()
                root_logger.info('Executing MAIN...')
                #main()
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
            if isinstance(e, SystemExit):
                break
            root_logger.exception('Exception: {} \n Args: {}'.format(e, e.args))
            start_main = True
            time.sleep(1)
            if error_count > 20:
                raise e
            else:
                error_count = error_count + 1
                pass
