VERSION = "1.9.9"

import sys
import os
import argparse
import requests
import logging
import logging.config
import logging.handlers
import time
import threading
import multiprocessing
from multiprocessing import Process as mp
from multiprocessing import cpu_count
from configparser import ConfigParser
from configparser import NoOptionError
from dateutil import parser as timeparser
from influxdb import InfluxDBClient
from datetime import datetime
from pyVmomi import vim
from pyVim import connect
from pycrypt.encryption import AESCipher
from vmware.vcenter import Vcenter
from statsd.collector import StatsCollector
from statsd.parse import Parser
from influx.client import InfluxDB


""" 
This script very specific to the vmcollector VMs being used to collect VM performance data.
 Each collector VM runs with 4 tasks each task handles a group of VMs. The goal is to be able to collect all VM stats
 with as granular sampling as possible, in which case for VMware is 20 second sample intervals.
"""


class Args:
    """
    Args Class handles the cmdline arguments passed to the code and
    parses through a conf file
    Usage can be stored to a variable or called by Args().<property>
    """

    def __init__(self):
        self.__aes_key = None

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

        # Parse through the provided conf
        parser = ConfigParser()
        parser.read(cmd_args.config_file)

        # [GLOBAL]
        self.bin = str(parser.get('global', 'WorkingDirectory'))
        self.tmpdir = str(parser.get('global', 'TempDirectory'))

        # [LOGGING]
        self.LOG_DIR = str(parser.get('logging', 'LogDir'))
        self.LOG_SIZE = parser.get('logging', 'LogRotateSizeMB')
        self.MAX_KEEP = parser.get('logging', 'MaxFilesKeep')
        self.secdir = parser.get('global', 'SecureDir')
        try:
            debug_check = parser.get('logging', 'Debug')
            if debug_check == 'True':
                self.DEBUG = True
        except NoOptionError:
            pass

        # [INFLUXDB]
        self.TelegrafIP = parser.get('influxdb', 'TelegrafIP')
        self.nonprod_port = parser.get('influxdb', 'nonprod_port')
        self.prod_port = parser.get('influxdb', 'prod_port')

        # [METRICS]
        self.vcenterNameOrIP = parser.get('metrics', 'vcenterNameOrIP')
        self.vcenterNameOrIP = [u.strip() for u in self.vcenterNameOrIP.split(',')]
        self.username = parser.get('metrics', 'username')
        self.__password = parser.get('metrics', 'password')
        if self.__password:
            self.store_passwd()

    def get_passwd(self):
        """
        Returns the stored encrypted password from memory
        :return: clear_text password
        """
        if self.__password:
            aes_cipher = AESCipher()
            return aes_cipher.decrypt(self.__password, self.__aes_key)

    def store_passwd(self, clr_passwd):
        """
        Takes the clear text password and stores it in a variable with AES encryption.
        :param clr_passwd:
        :return: None, stores the password in the protected __ variable
        """
        aes_cipher = AESCipher()
        self.__aes_key = aes_cipher.AES_KEY
        self.__password = aes_cipher.encrypt(clr_passwd)


class Logger:
    """
    Custom logging class that fits with how I prefere to log.
    There may be better or more proper ways of doing this but
    this works like a charm.
    This class stores all loggers into a property named loogers.
    A call to get_logger(name) will search for 'name' in loggers
    and if found return that logger, otherwise create a new one.
    """

    # Default log level. This can be changed at initialization of the object
    loglevel = logging.INFO

    def __init__(self, log_file='/var/log/collect_metrics.log',
                 error_log_file='/var/log/collect_metrics_err.log',
                 log_size_MB=10, max_logs=8,
                 formatter=logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s"),
                 log_level=logging.INFO):
        self.loggers = {}
        self.log_level = log_level
        self.log_file = log_file
        self.error_log_file = error_log_file

        self.formatter = formatter
        self.logsize = log_size_MB * 1048576
        self.max_logs = max_logs

    def get_logger(self, name):
        """
        Search self.loggers for the 'name' parameter value and if found
        return the already created logger, otherwise create a new one.
        This sets up a file logger for info and error/exception and an
        output stream for debugging. These logger types cannot be changed
        without overriding this method.
        :param name: Name of the logger to be searched for
        :return: logger
        """

        if self.loggers.get(name):
            return self.loggers.get(name)

        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)

        dfh = logging.StreamHandler(stream=sys.stdout)
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(self.formatter)

        lfh = logging.handlers.RotatingFileHandler(self.log_file,
                                                   mode='a',
                                                   maxBytes=self.logsize,
                                                   backupCount=self.max_logs,
                                                   encoding='utf8',
                                                   delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(self.formatter)

        efh = logging.handlers.RotatingFileHandler(self.error_log_file,
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


def new_bg_agents(num, sq, iq):
    args = Args()
    proc_pool = []
    # only need a single parser process as this process is as effecient as can be
    proc_pool.append(multiprocessing.Process(target=Parser, kwargs={'statsq': sq, 'influxq': iq}))
    for x in range(num):
        proc_pool.append(multiprocessing.Process(target=InfluxDB, kwargs={'influxq': iq,
                                                                          'host': args.TelegrafIP,
                                                                          'port': args.prod_port,
                                                                          'username': 'anonymous',
                                                                          'password': 'anonymous',
                                                                          'database': 'perf_stats',
                                                                          'timeout': 5,
                                                                          'retries': 3
                                                                          }
                                                 ))

    return proc_pool


def check_bg_process(proc_pool=[], proc=None):

    if proc:
        if not proc.is_alive():
            proc.start()
    elif proc_pool:
        for proc in proc_pool:
            if not proc.is_alive():
                proc.start()


def waiter(process_pool, timeout_secs=60):

    logger = LOGGERS.get_logger('Process Waiter')
    start_time = datetime.now()
    proc_status = {}
    for proc in process_pool:
        proc.start()
        logger.info('Process: {}, Started: {}'.format(proc.name, proc.is_alive()))
        proc_status.update({proc.name: proc.is_alive()})

    time.sleep(1)
    # Just going to loop until the timeout has been reached or all processes have completed
    while True:
        for proc in process_pool:
            # track the running status of each process True/False
            proc_status[proc.name] = proc.is_alive()

        # if all of the processes are not running any longer then break
        if list(proc_status.values()).count(False) == len(process_pool):
            logger.info('Process Status: {}'.format(proc_status))
            break
        # if the timeout value has been reached then break
        elif (datetime.now() - start_time).seconds >= timeout_secs:
            logger.error('Timeout Reached!')
            logger.info('Process Status: {}'.format(proc_status))
            break


def main(vcenter, sq, args):
    """
    This is the main worker. The dude abides!
    :return:
    """
    LOGGERS = Logger()
    main_logger = LOGGERS.get_logger('main')
    all_views = []
    vc = vcenter
    try:
        # This would be the Main program execution
        main_logger.info('Starting collect_metrics.py:  ARGS: {}'.format(args.__dict__))

        vc.connect()

        if not vc.content:
            raise BaseException('Unable to Connect to vCenter {}'.format(vcenter))

        if args.MOREF_TYPE.lower() == 'vm':
            all_views = vc.get_container_view([vim.VirtualMachine],
                                              filter_expression='runtime.powerState == poweredOn')
        elif args.MOREF_TYPE.lower() == 'host':
            all_views = vc.get_container_view([vim.HostSystem])

        elif args.MOREF_TYPE.lower() == 'cluster':
            all_views = vc.get_container_view([vim.ClusterComputeResource])

        if all_views:
            statsd = StatsCollector(vc)

            main_logger.info('Statsd Query Begin')
            statsd.query_stats(sq, all_views)

        vc.disconnect()

        return 0
    except BaseException as e:
        if vc.si:
            connect.Disconnect(vc.si)
        main_logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))


if __name__ == '__main__':

    args = Args()
    LOGGERS = Logger()

    root_logger = LOGGERS.get_logger("{}:{}".format(args.MOREF_TYPE, __name__))
    root_logger.info('Code Version : {}'.format(VERSION))
    error_count = 0
    sample_size = 3  # default sample_size value of 3 samples or 1 minute
    vcenter_pool = []

    if args.MOREF_TYPE.lower() == 'vm':
        sample_size = Vcenter.get_QuerySpec(vim.VirtualMachine, get_sample=True)
    elif args.MOREF_TYPE.lower() == 'host':
        sample_size = Vcenter.get_QuerySpec(vim.HostSystem, get_sample=True)
    main_program_running_threshold = (sample_size * 20) - 5  # 1 sample is 20 seconds

    # Setup the multiprocessing queues
    queue_manager = multiprocessing.Manager()
    # statsd_queue for the parser process
    sq = queue_manager.Queue()
    # influxdb_queue for the inlfuxdb process to send the stats
    iq = queue_manager.Queue()

    # Setup the background processes
    proc_pool = new_bg_agents(cpu_count(), sq, iq)
    root_logger.info('Starting parser subprocess')
    root_logger.info('Starting influxdb subprocess')
    [proc.start() for proc in proc_pool]

    # This code will be ran from a systemd service
    # so this needs to be an infinite loop
    while True:

        # check if the background process for parsing and influx are still running
        check_bg_process(proc_pool=proc_pool)

        try:
            # Perform a VERSION check with the code and if there is an update then restart the agent
            with open(os.path.realpath(__file__), 'r') as f:
                line = f.readline()
                f.close()
            code_version = line.split("=")[1].replace('\"', '').strip('\n').strip()
            if not code_version == VERSION:
                logging.info("Code Version change from current version {} to new version {}".format(VERSION,
                                                                                                    code_version))
                # Exit the agent.
                # Since the agent should be ran as a service then the agent should automatically be restarted
                sys.exit(-1)

            start_main = True
            if start_main:
                start_main = False
                start_time = datetime.now()
                root_logger.info('Executing MAIN Processes...')
                # execute the main function as a process so that it can be monitored for running time
                process_pool = []
                vcenter_pool = []
                for vcenter in args.vcenterNameOrIP:
                    vc = Vcenter(name=vcenter, username=args.username)
                    vcenter_pool.append(vc)
                    process_pool.append(mp(target=main,
                                           kwargs={'vcenter': vc,
                                                   'sq': sq,
                                                   'args': args
                                                   }
                                           ))
                # Join the process so that the While loop is halted until the process is complete
                # or times out after max_running_threshold seconds
                waiter(process_pool, main_program_running_threshold)

                # if the process has been running for longer than 60 seconds then
                # the program releases control back to root. This is a condition
                # check to see if that is indeed what happened
                for proc in process_pool:
                    if proc.is_alive():
                        # process ran longer than 60 seconds and since collection times are in 60 second intervals
                        # this main process needs to be terminated and restarted
                        proc.terminate()
                        root_logger.error(
                            'MAIN process {} running too long. Start Time: {}, End Time: {}'.format(proc.name,
                                                                                                    start_time.ctime(),
                                                                                                    datetime.now().ctime()))
                        start_main = True

                        # TODO: add an alerting module that sends an alert either through email or snmp

                end_time = datetime.now()
                root_logger.info('Execution Completed in {} seconds'.format((end_time - start_time).seconds))

            # evaluate the timing to determine how long to sleep
            #  since pulling X minutes of perf data then should sleep
            #  sample interval time minus the execution time
            #  reduce that time by 20 seconds to allow for the initial connections at main start

            exec_time_delta = end_time - start_time
            sleep_time = main_program_running_threshold - int(exec_time_delta.seconds)
            if sleep_time >= 1:
                time.sleep(sleep_time)
            time.sleep(1)
            error_count = 0
            for v in vcenter_pool:
                if v.content:
                    v.disconnect()
        except BaseException as e:
            if isinstance(e, SystemExit):
                logging.info('Agent exiting..')
                logging.info('Parser process exiting..')
                logging.info('InfluxDB process exiting..')
                for proc in proc_pool:
                    proc.terminate()
                for v in vcenter_pool:
                    if v.content:
                        v.disconnect()
                break
            root_logger.exception('Exception: {} \n Args: {}'.format(e, e.args))
            start_main = True
            time.sleep(1)
            for v in vcenter_pool:
                if v.content:
                    v.disconnect()
            if error_count > 20:
                raise e
            else:
                error_count = error_count + 1
                pass
    # final catch all background process termination
    if proc_pool:
        for proc in proc_pool:
            proc.terminate()
    for v in vcenter_pool:
        if v._connected:
            v.disconnect()
