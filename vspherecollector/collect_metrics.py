VERSION = "2.3.6-17"
"""
This code is very specific to the ollector VMs being used to collect VM performance data.
The goal is to be able to collect all VM stats with as granular sampling as possible, in 
which case for VMware is 20 second sample intervals.
"""

import sys
import os
import atexit
import time
import logging
import queue
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
from vspherecollector.datadog.handle import Datadog
from vspherecollector.log.setup import LoggerSetup
from vspherecollector.args.handle import Args


BASE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = BASE_DIR.replace(os.path.basename(BASE_DIR), '')
sys.path.append(BASE_DIR)

args = Args()

log_setup = LoggerSetup(yaml_file=f'{BASE_DIR}/logging_config.yml')
if args.DEBUG:
    log_setup.set_loglevel(loglevel='DEBUG')

log_setup.setup()

logger = logging.getLogger(__name__)

vcenter_list = []
proc_pool = []


def restart_proc(proc):
    """
    Function to restart the background processes
    :param proc:
    :return: None
    """
    try:
        logger.debug(f'restart_proc initializing')
        if hasattr(proc, '_target'):
            logger.debug(f'proc_info: name={proc.name}, target={proc._target.__name__}, kwargs={proc._kwargs.__str__()}')
            new_proc = multiprocessing.Process(name=proc.name,
                                               target=proc._target,
                                               kwargs=proc._kwargs,
                                               )
            logger.debug(f'new_proc.start(): {proc.name}')
            new_proc.start()
            return new_proc
    except BaseException as e:
        logger.exception(f'Exception: {e}, \n Args: {e.args}')


def new_bg_agents(num, sq, iq, aq, atq, dq):
    """
    Creates new background agents based on the CPU count of the VM

    :param num: Number of processes to initiallize for each services
    :param sq: statsd queue used by the parser
    :param iq: influxdb queue
    :param aq: agent queue used by the statsd
    :param atq: agent trcker queue
    :param dq: datadog queue
    :return: multiprocessor pool
    """
    logger = logging.getLogger(f'{__name__}.new_bg_agents')
    try:
        args = Args()
        proc_pool = []

        for x in range(int(num)):
            proc_pool.append(multiprocessing.Process(name=f'influx_proc_{x}',
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
            proc_pool.append(multiprocessing.Process(name=f'statsd_proc_{x}',
                                                     target=Statsd,
                                                     kwargs={'vcenter_list': vcenter_list,
                                                             'in_q': aq,
                                                             'out_q': sq,
                                                             'tracker_q': atq
                                                             }
                                                     ))
            proc_pool.append(multiprocessing.Process(name=f'parser_proc_{x}',
                                                     target=Parser,
                                                     kwargs={'statsq': sq, 'influxq': iq, 'datadogq': dq}))

            # proc_pool.append(multiprocessing.Process(name=f'datadog_proc_{x}',
            #                                          target=Datadog,
            #                                          kwargs={
            #                                              'config_file': f'{BASE_DIR}/datadog_config.conf',
            #                                              'bg_process': True,
            #                                              'ddq': dq}))

        return proc_pool
    except BaseException as e:
        logger.exception('Exception: {e}, \n Args: {e.args}')
    return None


def check_bg_process(proc=None):
    """
    Multiprocess check to see if the processes are alive or not and restarts it if necessary
    :param proc:
    :return:
    """
    global proc_pool

    new_proc_pool = proc_pool.copy()
    logger = logging.getLogger(f'{__name__}.check_bg_processes')
    try:
        if proc:
            if not proc.is_alive():
                logger.debug(f'Process: {proc.name}, Not Alive')
                if proc.pid:
                    logger.debug(f'Process: {proc.name}, PID: {proc.pid}, ExitCode {proc.exitcode}')
                    proc.terminate()
                logger.info(f'Process: {proc.name}, Starting Process')
                restart_proc(proc)
        elif proc_pool:
            for proc in proc_pool:
                if not proc.is_alive():
                    logger.debug(f'Process: {proc.name}, Not Alive')
                    if proc.pid:
                        logger.debug(f'Process: {proc.name}, PID: {proc.pid}, ExitCode {proc.exitcode}')
                        proc.terminate()
                    logger.info(f'Process: {proc.name}, Starting Process')
                    new_proc_pool.remove(proc)
                    new_proc_pool.append(restart_proc(proc))
        proc_pool = new_proc_pool
    except BaseException as e:
        logger.exception(f'Proc: {proc.name}, Exception: {e}, \n Args: {e.args}')
        raise e


def waiter(process_pool, timeout_secs=60):
    """
    Multiprocess waiter function to wait for the functions to end or until timeout at timeout_secs
    :param process_pool:
    :param timeout_secs:
    :return:
    """
    logger = logging.getLogger(f'{__name__}.waiter')
    start_time = datetime.now()
    proc_status = {}
    for proc in process_pool:
        proc.start()
        logger.info(f'Process: {proc.name}, Started: {proc.is_alive()}')
        proc_status.update({proc.name: proc.is_alive()})

    time.sleep(1)
    # Just going to loop until the timeout has been reached or all processes have completed
    while True:
        for proc in process_pool:
            # track the running status of each process True/False
            proc_status[proc.name] = proc.is_alive()

        # if all of the processes are not running any longer then break
        if list(proc_status.values()).count(False) == len(process_pool):
            logger.info(f'Process Status: {proc_status}')
            break
        # if the timeout value has been reached then break
        elif (datetime.now() - start_time).seconds >= timeout_secs:
            logger.error(f'Timeout Reached!')
            logger.info(f'Process Status: {proc_status}')
            break


def main(vcenter, agentq, agentrackq, args, collector_type):
    """
    This is the main worker. The dude abides!
    :return:
    """

    main_logger = logging.getLogger(f'{__name__}.{collector_type}.main_func')
    all_views = []
    vc = vcenter
    try:
        # This would be the Main program execution
        main_logger.info(f'Starting collect_metrics.py:  ARGS: {args.__dict__}')

        vc.connect()
        atexit.register(vc.disconnect)

        if not vc.content:
            raise BaseException(f'Unable to Connect to vCenter {vcenter}')

        if collector_type.lower() == 'vm':
            main_logger.debug(f"Collecting views for 'vim.VirtualMachine'")
            all_views = []
            ds_views = []
            cl_view_tracker = []
            cl_ds_view_tracker = []
            for dc in vc.get_container_view([vim.Datacenter]):
                all_vm_views = vc.get_container_view([vim.VirtualMachine],
                                                     search_root=dc,
                                                     filter_expression='runtime.powerState == poweredOn')
                all_ds_views = vc.get_container_view([vim.Datastore],
                                                     search_root=dc)
                for cl in vc.get_container_view([vim.ClusterComputeResource], search_root=dc):
                    main_logger.debug(f"Collecting PoweredOn VMs for cluster {cl.name}")
                    all_cl_views = vc.get_container_view([vim.VirtualMachine],
                                                         search_root=cl,
                                                         filter_expression='runtime.powerState == poweredOn')
                    main_logger.debug(f'Found {len(all_cl_views)} VMs in cluster {cl.name}')

                    all_cl_ds_views = None
                    if all_cl_views:
                        all_cl_ds_views = cl.datastore
                        cl_view_tracker = cl_view_tracker.__add__(all_cl_views)
                        all_views = all_views.__add__(list(
                            zip(all_cl_views,
                                [dc.name] * len(all_cl_views),
                                [cl.name] * len(all_cl_views)
                                )
                        ))
                    if all_cl_ds_views:
                        cl_ds_view_tracker = cl_ds_view_tracker.__add__(all_cl_ds_views)
                        ds_views = ds_views.__add__(list(
                            zip(all_cl_ds_views,
                                [dc.name] * len(all_cl_ds_views),
                                [cl.name] * len(all_cl_ds_views)
                                )
                        ))
                no_cl_views = list(set(all_vm_views) - set(cl_view_tracker))
                no_cl_ds_views = list(set(all_ds_views) - set(cl_view_tracker))

                if no_cl_views:
                    main_logger.debug(f'Found {len(no_cl_views)} VMs not in any Cluster')
                    # These have no cluster
                    all_views = all_views.__add__(list(
                        zip(no_cl_views,
                            [dc.name] * len(no_cl_views),
                            ['NoCluster'] * len(no_cl_views)
                            )
                    ))

                if no_cl_ds_views:
                    # These have no cluster
                    ds_views = ds_views.__add__(list(
                        zip(no_cl_ds_views,
                            [dc.name] * len(no_cl_ds_views),
                            ['NoCluster'] * len(no_cl_ds_views)
                            )
                    ))

        if collector_type.lower() == 'datastore':
            main_logger.debug(f"Collecting views for 'vim.Datastore'")
            all_views = []
            cl_view_tracker = []
            cl_ds_view_tracker = []
            for dc in vc.get_container_view([vim.Datacenter]):
                all_ds_views = vc.get_container_view([vim.Datastore],
                                                     search_root=dc)
                for cl in vc.get_container_view([vim.ClusterComputeResource], search_root=dc):
                    main_logger.debug(f"Collecting Datastores for cluster {cl.name}")

                    all_cl_ds_views = cl.datastore

                    if all_cl_ds_views:
                        cl_ds_view_tracker = cl_ds_view_tracker.__add__(all_cl_ds_views)
                        all_views = all_views.__add__(list(
                            zip(all_cl_ds_views,
                                [dc.name] * len(all_cl_ds_views),
                                [cl.name] * len(all_cl_ds_views)
                                )
                        ))
                no_cl_ds_views = list(set(all_ds_views) - set(cl_view_tracker))

                if no_cl_ds_views:
                    # These have no cluster
                    all_views = all_views.__add__(list(
                        zip(no_cl_ds_views,
                            [dc.name] * len(no_cl_ds_views),
                            ['NoCluster'] * len(no_cl_ds_views)
                            )
                    ))

        elif collector_type.lower() == 'host':
            main_logger.debug(f"Collecting views for 'vim.HostSystem'")
            all_views = []
            cl_view_tracker = []
            for dc in vc.get_container_view([vim.Datacenter]):
                all_host_views = vc.get_container_view([vim.HostSystem], search_root=dc)
                for cl in vc.get_container_view([vim.ClusterComputeResource], search_root=dc):
                    main_logger.debug(f"Collecting Esxi hosts for cluster {cl.name}")
                    all_cl_views = vc.get_container_view([vim.HostSystem],
                                                         search_root=cl)
                    if all_cl_views:
                        main_logger.debug(f'Found {len(all_cl_views)} hosts in cluster {cl.name}')
                        cl_view_tracker = cl_view_tracker.__add__(all_cl_views)
                        all_views = all_views.__add__(list(
                            zip(all_cl_views,
                                [dc.name] * len(all_cl_views),
                                [cl.name] * len(all_cl_views)
                                )
                        ))
                no_cl_views = list(set(all_host_views) - set(cl_view_tracker))
                if no_cl_views:
                    main_logger.debug(f'Found {len(no_cl_views)} hosts not in any Cluster')
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

            main_logger.info(f'Statsd Query Begin')
            # send thr views to the statsd collector queue
            statsd.query_stats(agentq, agentrackq, all_views)

        vc.disconnect()

        return 0
    except BaseException as e:
        if vc.si:
            connect.Disconnect(vc.si)
        main_logger.exception(f'Exception: {e}, \n Args: {e.args}')


if __name__ == '__main__':
    args = Args()
    watch_24_start = datetime.now()

    try:
        # root_logger.info('Code Version : {VERSION}')
        error_count = 0
        sample_size = 15  # default sample_size value of 3 samples or 1 minute
        vcenter_pool = []

        main_program_running_threshold = args.running_threshold
        over_watch_threshold = 86400 - 13  # 24 hours - 13 seconds

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
        # datadog_queue for the datadog process to send the stats
        dq = queue_manager.Queue()

        # Setup the background processes
        vcenter_list = args.vcenterNameOrIP
        proc_pool = new_bg_agents(cpu_count(), sq, iq, aq, atq, dq)

        # This code will be ran from a systemd service
        # so this needs to be an infinite loop
        while True:
            try:
                logger.info(f'Code Version : {VERSION}')
                watch_24_now = datetime.now()
                watch_delta = watch_24_now - watch_24_start
                logger.info(f"Service Time Remaining Before Service Restart: {over_watch_threshold - watch_delta.seconds} second(s)")
                if watch_delta.seconds >= over_watch_threshold:
                    logging.info(
                        f"Overall runtime running {watch_delta.seconds} seconds. Restarting the program to flush memory and processes")
                    # Exit the agent.
                    try:
                        # Wait for the influx_q to be flushed
                        while not iq.empty() or dq.empty():
                            logger.debug(f'Waiting on the influx_q to flush out before restarting the program...')
                    except queue.Empty:
                        sys.exit(-1)
                        break
                    except BaseException:
                        sys.exit(-1)
                        break

                    # Since the agent should be ran as a service then the agent should automatically be restarted
                    for proc in proc_pool:
                        proc.terminate()
                    sys.exit(-1)

                # check if the background process for parsing and influx are still running
                check_bg_process()

                # Perform a VERSION check with the code and if there is an update then restart the agent
                with open(os.path.realpath(__file__), 'r') as f:
                    line = f.readline()
                    f.close()
                code_version = line.split("=")[1].replace('\"', '').strip('\n').strip()
                if not code_version == VERSION:
                    logging.info(f"Code Version change from current version {VERSION} to new version {code_version}")
                    # Exit the agent.
                    # Since the agent should be ran as a service then the agent should automatically be restarted
                    for proc in proc_pool:
                        proc.terminate()
                    sys.exit(-1)

                start_main = True
                if start_main:
                    start_main = False
                    start_time = datetime.now()
                    logger.info(f'Executing MAIN Processes...')
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
                            logger.error(
                                f'MAIN process {proc.name} running too long. Start Time: {start_time.ctime()}, End Time: {datetime.now().ctime()}')
                            start_main = True

                            # TODO: add an alerting module that sends an alert either through email or snmp

                    end_time = datetime.now()
                    logger.info(f'Execution Completed in {(end_time - start_time).seconds} seconds')

                # evaluate the timing to determine how long to sleep
                #  since pulling X minutes of perf data then should sleep
                #  sample interval time minus the execution time
                #  reduce that time by 20 seconds to allow for the initial connections at main start

                exec_time_delta = end_time - start_time
                sleep_time = main_program_running_threshold - int(exec_time_delta.seconds)
                logger.info(f'Waiting for {sleep_time} seconds to start again.')
                if sleep_time >= 1:
                    time.sleep(sleep_time)
                time.sleep(1)
                sys.exit(-1)
                error_count = 0
                # for v in vcenter_pool:
                #     if v.content:
                #         v.disconnect()
            except BaseException as e:
                if isinstance(e, SystemExit):
                    logging.info(f'Agent exiting..')
                    logging.info(f'Process pool terminating..')
                    for proc in proc_pool:
                        proc.terminate()
                    for v in vcenter_pool:
                        if v.content:
                            v.disconnect()
                    break
                logger.exception(f'Exception: {e} \n Args: {e.args}')
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
        sys.exit(-1)
    except BaseException as e:
        if isinstance(e, SystemExit):
            logging.info(f'Agent exiting..')
            logging.info(f'Process pool terminating..')
            for proc in proc_pool:
                proc.terminate()
            for v in vcenter_pool:
                if v.content:
                    v.disconnect()
        else:
            logger.exception(f'Exception: {e} \n Args: {e.args}')
