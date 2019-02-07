VERSION = "2.0.5"

import sys
import os
import atexit
import time
import logging
import multiprocessing
from multiprocessing import Process as mp
from multiprocessing import cpu_count
from configparser import ConfigParser
from configparser import NoOptionError
from datetime import datetime
from pyVmomi import vim
from pyVmomi import vmodl
from pyVim import connect
from pycrypt.encryption import AESCipher
from vspherecollector.vmware.vcenter import Vcenter
from vspherecollector.statsd.agent import Statsd
from vspherecollector.statsd.collector import StatsCollector
from vspherecollector.statsd.parse import Parser
from vspherecollector.influx.client import InfluxDB
from vspherecollector.logger.handle import Logger
from vspherecollector.args.handle import Args


""" 
This script very specific to the vmcollector VMs being used to collect VM performance data.
 Each collector VM runs with 4 tasks each task handles a group of VMs. The goal is to be able to collect all VM stats
 with as granular sampling as possible, in which case for VMware is 20 second sample intervals.
"""


args = Args()
# log_level = logging.INFO
# if args.DEBUG:
#     log_level = logging.DEBUG
LOGGERS = Logger()


def new_bg_agents(num, sq, iq, aq, atq, vcenter_list):
    logger = LOGGERS.get_logger('new_bg_agents')
    try:
        args = Args()
        proc_pool = []
        # only need a single parser process as this process is as effecient as can be

        # for x in range(int(2)):

        for x in range(int(num)):
            proc_pool.append(multiprocessing.Process(name='influx_proc_{}'.format(x),
                                                     target=InfluxDB,
                                                     kwargs={'influxq': iq,
                                                             'host': args.TelegrafIP,
                                                             'port': args.prod_port,
                                                             'username': 'anonymous',
                                                             'password': 'anonymous',
                                                             'database': 'perf_stats',
                                                             'timeout': 5,
                                                             'retries': 3,
                                                             }
                                                     ))
            proc_pool.append(multiprocessing.Process(name='statsd_proc_{}'.format(x),
                                                     target=Statsd,
                                                     kwargs={'vcenter_list': vcenter_list,
                                                             'in_q': aq,
                                                             'out_q': sq,
                                                             'tracker_q': atq
                                                             }
                                                     ))
            proc_pool.append(multiprocessing.Process(name='parser_proc_{}'.format(x),
                                                     target=Parser,
                                                     kwargs={'statsq': sq, 'influxq': iq}))

        return proc_pool
    except BaseException as e:
        logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))
    return None


def check_bg_process(proc_pool=[], proc=None):
    logger = LOGGERS.get_logger('check_bg_processes')
    try:
        if proc:
            if not proc.is_alive():
                logger.debug('Process: {}, Not Alive'.format(proc.name))
                if proc.pid:
                    logger.debug('Process: {}, PID: {}, ExitCode {}'.format(proc.name, proc.pid, proc.exitcode))
                    proc.terminate()
                logger.info('Process: {}, Starting Process'.format(proc.name))
                proc.start()
        elif proc_pool:
            for proc in proc_pool:
                if not proc.is_alive():
                    logger.debug('Process: {}, Not Alive'.format(proc.name))
                    if proc.pid:
                        logger.debug('Process: {}, PID: {}, ExitCode {}'.format(proc.name, proc.pid, proc.exitcode))
                        proc.terminate()
                    logger.info('Process: {}, Starting Process'.format(proc.name))
                    proc.start()
    except BaseException as e:
        logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))


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


def main(vcenter, agentq, agentrackq, args, collector_type):
    """
    This is the main worker. The dude abides!
    :return:
    """
    log_level = logging.INFO
    if args.DEBUG:
        log_level = logging.DEBUG

    LOGGERS = Logger(log_level=log_level)
    main_logger = LOGGERS.get_logger('main')
    all_views = []
    vc = vcenter
    try:
        # This would be the Main program execution
        main_logger.info('Starting collect_metrics.py:  ARGS: {}'.format(args.__dict__))

        vc.connect()
        atexit.register(vc.disconnect)

        if not vc.content:
            raise BaseException('Unable to Connect to vCenter {}'.format(vcenter))

        if collector_type.lower() == 'vm':
            main_logger.debug("Collecting views for 'vim.VirtualMachine'")
            all_views = []
            cl_view_tracker = []
            for dc in vc.get_container_view([vim.Datacenter]):
                all_vm_views = vc.get_container_view([vim.VirtualMachine],
                                                     search_root=dc,
                                                     filter_expression='runtime.powerState == poweredOn')
                for cl in vc.get_container_view([vim.ClusterComputeResource], search_root=dc):
                    main_logger.debug("Collecting PoweredOn VMs for cluster {}".format(cl.name))
                    all_cl_views = vc.get_container_view([vim.VirtualMachine],
                                                         search_root=cl,
                                                         filter_expression='runtime.powerState == poweredOn')
                    main_logger.debug('Found {} VMs in cluster {}'.format(len(all_cl_views), cl.name))
                    if all_cl_views:
                        cl_view_tracker = cl_view_tracker.__add__(all_cl_views)
                        all_views = all_views.__add__(list(
                            zip(all_cl_views,
                                [dc.name] * len(all_cl_views),
                                [cl.name] * len(all_cl_views)
                                )
                        ))
                no_cl_views = list(set(all_vm_views) - set(cl_view_tracker))
                if no_cl_views:
                    main_logger.debug('Found {} VMs not in any Cluster'.format(len(no_cl_views)))
                    # These have no cluster
                    all_views = all_views.__add__(list(
                        zip(no_cl_views,
                            [dc.name] * len(no_cl_views),
                            ['NoCluster'] * len(no_cl_views)
                            )
                    ))

        elif collector_type.lower() == 'host':
            main_logger.debug("Collecting views for 'vim.HostSystem'")
            all_views = []
            cl_view_tracker = []
            for dc in vc.get_container_view([vim.Datacenter]):
                all_host_views = vc.get_container_view([vim.HostSystem], search_root=dc)
                for cl in vc.get_container_view([vim.ClusterComputeResource], search_root=dc):
                    main_logger.debug("Collecting Esxi hosts for cluster {}".format(cl.name))
                    all_cl_views = vc.get_container_view([vim.HostSystem],
                                                         search_root=cl)
                    if all_cl_views:
                        main_logger.debug('Found {} hosts in cluster {}'.format(len(all_cl_views), cl.name))
                        cl_view_tracker = cl_view_tracker.__add__(all_cl_views)
                        all_views = all_views.__add__(list(
                            zip(all_cl_views,
                                [dc.name] * len(all_cl_views),
                                [cl.name] * len(all_cl_views)
                                )
                        ))
                no_cl_views = list(set(all_host_views) - set(cl_view_tracker))
                if no_cl_views:
                    main_logger.debug('Found {} hosts not in any Cluster'.format(len(no_cl_views)))
                    # These have no cluster
                    all_views = all_views.__add__(list(
                        zip(no_cl_views,
                            [dc.name] * len(no_cl_views),
                            ['NoCluster'] * len(no_cl_views)
                            )
                    ))

        elif collector_type.lower() == 'cluster':
            all_views = vc.get_container_view([vim.ClusterComputeResource])

        if all_views:
            statsd = StatsCollector(vc)

            main_logger.info('Statsd Query Begin')
            statsd.query_stats(agentq, agentrackq, all_views)

        vc.disconnect()

        return 0
    except BaseException as e:
        if vc.si:
            connect.Disconnect(vc.si)
        main_logger.exception('Exception: {}, \n Args: {}'.format(e, e.args))


if __name__ == '__main__':
    args = Args()
    root_logger = LOGGERS.get_logger("{}:{}".format(args.MOREF_TYPE, __name__))
    try:
        root_logger.info('Code Version : {}'.format(VERSION))
        error_count = 0
        sample_size = 3  # default sample_size value of 3 samples or 1 minute
        vcenter_pool = []

        # if args.MOREF_TYPE.lower() == 'vm':
        sample_size = Vcenter.get_QuerySpec(vim.VirtualMachine, get_sample=True)
        # elif args.MOREF_TYPE.lower() == 'host':
        #     sample_size = Vcenter.get_QuerySpec(vim.HostSystem, get_sample=True)
        main_program_running_threshold = (sample_size * 20) - 5  # 1 sample is 20 seconds

        # Setup the multiprocessing queues
        queue_manager = multiprocessing.Manager()
        # statsd_queue for the parser process
        sq = queue_manager.Queue()
        # influxdb_queue for the inlfuxdb process to send the stats
        iq = queue_manager.Queue()
        # agent_queue for the statsd process to query perfmanager
        aq = queue_manager.Queue()
        # agent_tracker_queue for the statsd process to query perfmanager
        atq = queue_manager.Queue()

        # Setup the background processes
        proc_pool = new_bg_agents(cpu_count(), sq, iq, aq, atq, args.vcenterNameOrIP)

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
                    for proc in proc_pool:
                        proc.terminate()
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
                                                       'agentq': aq,
                                                       'agentrackq': atq,
                                                       'args': args,
                                                       'collector_type': args.MOREF_TYPE.lower()
                                                       },
                                               name=vcenter
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
                # for v in vcenter_pool:
                #     if v.content:
                #         v.disconnect()
            except BaseException as e:
                if isinstance(e, SystemExit):
                    logging.info('Agent exiting..')
                    logging.info('Process pool terminating..')
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
            if v.content:
                v.disconnect()
    except BaseException as e:
        root_logger.exception('Exception: {} \n Args: {}'.format(e, e.args))