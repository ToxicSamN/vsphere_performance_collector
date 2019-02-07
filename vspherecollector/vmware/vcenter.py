
import os
import re
import ssl
import atexit
import logging
from datetime import datetime
from datetime import timedelta
from pyVmomi import vim
from pyVmomi import vmodl
from pyVim import connect
from pycrypt.encryption import AESCipher
from vspherecollector.vmware.credentials.credstore import Credential
from vspherecollector.logger.handle import Logger


LOGGERS = Logger()


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
    def __init__(self, name, username=None, password=None, ssl_context=None, _loggers=None):
        self.cipher = AESCipher()
        self.si = None
        self.content = None
        self.cookies = None
        self.vcenter = name
        self.name = name
        self.username = username
        self.__password = self.store_password(password)
        self.ssl_context = ssl_context

        if _loggers:
            global LOGGERS
            LOGGERS = _loggers

    def store_password(self, password):
        if password:
            return self.cipher.encrypt(password)
        return None

    def retrieve_password(self):
        if self.__password:
            return self.cipher.decrypt(self.__password, self.cipher.AES_KEY)
        return None

    def connect(self):
        """
        validate whether username/password were passed or whether a private key should be used
        logger lines have been commented out until logging is fully implemented
        :return:
        """
        # TODO: Ensure logging is setup properly to reinstate the logger lines
        logger = LOGGERS.get_logger('connect_vcenter')

        try:
            # if no ssl_context has been provided then set this to unverified context
            if not self.ssl_context:
                self.ssl_context = ssl._create_unverified_context()
                self.ssl_context.verify_mode = ssl.CERT_NONE

            logger.debug('Getting Credential Information')

            if not self.__password and not self.username:
                logger.debug('No username and password provided. Will read from credstore for default account')
                cred = Credential('oppvfog01')
                cred_dict = cred.get_credential()
                self.username = cred_dict.get('username', None)
                self.__password = self.store_password(cred_dict.get('password', None))
                cred_dict = None
            elif self.username and not self.__password:
                logger.debug('Username provided but no Password. Will retrieve password from credstore')
                cred = Credential(self.username)
                cred_dict = cred.get_credential()
                self.username = cred_dict.get('username', None)
                self.__password = self.store_password(cred_dict.get('password', None))
                cred_dict = None
            logger.info('Connecting to vCenter {}'.format(self.vcenter))
            logger.debug(
                'Connection Params: vCenter: {}, Username: {}, {}, SSL_Context: {}'.format(self.vcenter,
                                                                                           self.username,
                                                                                           self.__password,
                                                                                           self.ssl_context))
            self.si = connect.SmartConnect(host=self.vcenter,
                                           user=self.username,
                                           pwd=self.retrieve_password(),
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
        logger = LOGGERS.get_logger('connect_vcenter')
        logger.info('Disconnecting vCenter {}'.format(self.vcenter))
        connect.Disconnect(self.si)

    def get_container_view(self, view_type, search_root=None, filter_expression=None, recursive=True):
        """
        Custom container_view function that allows the option for a filtered expression such as name == john_doe
        This is similar to the Where clause in powershell, however, this is case sensative.
        This function does not handle multiple evaluations such as 'and/or'. This can only evaluate a single expression.
        :param view_type: MoRef type [vim.VirtualMachine] , [vim.HostSystem], [vim.ClusterComputeResource], ect
        :param search_root: ManagedObject to search from, by default this is rootFolder
        :param filter_expression: Only return results that match this expression
        :param recursive: True|False
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
                    if not o.propSet[0].val == value:
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
                                                                      recursive=recursive)
        view = view_reference.view
        view_reference.Destroy()

        if filter_expression and view:

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
    def get_QuerySpec(managed_object, metric_id=None, get_sample=False, vm_sample_size=15, host_sample_size=15):
        """
        This will return a QuerySpec based on the managed_object type provided.
        vim.HostSystem and vim.VirtualMachine both have realtime stats, however,
        vim.ClusterComputeResource only has daily.
        :param managed_object:
        :param metric_id:
        :param get_sample:
        :param vm_sample_size:
        :param host_sample_size:
        :return:
        """
        # TODO: Provide the sample sizes via config file
        vm_sample = vm_sample_size
        host_sample = host_sample_size

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