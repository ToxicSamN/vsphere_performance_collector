VERSION = "1.0.0-9"
"""
This script very specific to the vmcollector VMs being used to collect VM performance data.
 Each collector VM runs with 4 tasks each task handles a group of VMs. The goal is to be able to collect all VM stats
 with as granular sampling as possible, in which case for VMware is 20 second sample intervals.
"""

import sys
import os
import time
import logging
import queue
import multiprocessing
from multiprocessing import Process as mp
from requests.exceptions import HTTPError
from datetime import datetime
from vspherecollector.vmware.rest.client import CimSession
from vspherecollector.vmware.rest.service import VCSAService
from vspherecollector.vmware.credentials.credstore import Credential
from vspherecollector.vmware.rest.exceptions import VcenterServiceUnavailable, SessionAuthenticationException
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

logger = logging.getLogger(f'vcServices.{__name__}')

vcenter_list = []
proc_pool = []


def restart_proc(proc):
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


def new_bg_agents(num, iq, dq):
    logger = logging.getLogger(f'{__name__}.new_bg_agents')
    try:
        args = Args()
        proc_pool = []
        # only need a single parser process as this process is as effecient as can be

        # for x in range(int(2)):

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

            proc_pool.append(multiprocessing.Process(name=f'datadog_proc_{x}',
                                                     target=Datadog,
                                                     kwargs={
                                                         'config_file': f'{BASE_DIR}/datadog_config.conf',
                                                         'bg_process': True,
                                                         'ddq': dq}))

        return proc_pool
    except BaseException as e:
        logger.exception('Exception: {e}, \n Args: {e.args}')
    return None


def check_bg_process(proc=None):
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


def main(cim, influxq, datadogq):
    main_logger = logging.getLogger(f'vcServices.{cim.vcenter}')

    # intial sleep timer to align the run times to every 10 seconds
    time.sleep(10 - (datetime.now().second % 10))

    while True:
        try:
            dt = datetime.utcnow()
            main_logger.info(f"Collecting at : {dt}")
            cim.login()
            svc = VCSAService(cim_session=cim)
            influxq.put(svc.list_all_services())
            # Todo: datadog q is not used at this time

            influx_json = {
                'time': dt,
                'measurement': 'vCenterAvailability',
                'fields': {
                    'available': 1,
                    'unavailable': 0
                },
                'tags': {
                    'vcenter': cim.vcenter
                }
            }
            influxq.put_nowait(influx_json)

        except SessionAuthenticationException as e:
            main_logger.exception(e)
        except VcenterServiceUnavailable as e:
            influx_json = {
                'time': dt,
                'measurement': 'vCenterAvailability',
                'fields': {
                    'available': 0,
                    'unavailable': 1
                },
                'tags': {
                    'vcenter': cim.vcenter
                }
            }
            influxq.put_nowait(influx_json)
            main_logger.exception(e)
        except HTTPError as e:
            main_logger.exception(e)
            if e.response.status_code == 401:
                # login session expired
                main_logger.info("Possible Session timeout. Run cim.login()")
                cim.login()

        # need to run every 10 seconds
        time.sleep(10 - (datetime.now().second % 10))


if __name__ == '__main__':
    args = Args()
    watch_60_start = datetime.now()

    try:
        # root_logger.info('Code Version : {VERSION}')
        error_count = 0
        sample_size = 15  # default sample_size value of 3 samples or 1 minute
        vcenter_pool = []

        main_program_running_threshold = 3600
        over_watch_threshold = 3600

        # Setup the multiprocessing queues
        queue_manager = multiprocessing.Manager()
        iq = queue_manager.Queue(100)
        # datadog_queue for the datadog process to send the stats
        dq = queue_manager.Queue(100)
        # queue_manager.start()

        # Setup the background processes
        vcenter_list = args.vcenterNameOrIP
        proc_pool = new_bg_agents(1, iq, dq)

        # This code will be ran from a systemd service
        # so this needs to be an infinite loop
        while True:
            try:
                logger.info(f'Code Version : {VERSION}')
                watch_60_now = datetime.now()
                watch_delta = watch_60_now - watch_60_start
                logger.info(
                    f"Service Time Remaining Before Service Restart: {over_watch_threshold - watch_delta.seconds} second(s)")
                if watch_delta.seconds >= over_watch_threshold:
                    logging.info(
                        f"Overall runtime running {watch_delta.seconds} seconds. Restarting the program to flush memory and processes")
                    # shutdown the queue.
                    try:
                        # Wait for the influx_q to be flushed
                        while not iq.empty() or dq.empty():
                            logger.debug(f'Waiting on the influx_q to flush out before restarting the program...')
                    except queue.Empty:
                        queue_manager.shutdown()
                    except BaseException:
                        queue_manager.shutdown()

                    # Since the agent should be ran as a service then the agent should automatically be restarted
                    for proc in proc_pool:
                        proc.terminate()

                    queue_manager.start()

                # check if the background process for parsing and influx are still running
                check_bg_process()

                # Perform a VERSION check with the code and if there is an update then restart the agent
                with open(os.path.realpath(__file__), 'r') as f:
                    line = f.readline()
                    f.close()
                code_version = line.split("=")[1].replace('\"', '').strip('\n').strip()
                if not code_version == VERSION:
                    logging.info(f"Code Version change from current version {VERSION} to new version {code_version}")
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
                    cred = Credential(username='oppvmwre')
                    c = cred.get_credential()
                    for vcenter in args.vcenterNameOrIP:
                        cim = CimSession(
                            vcenter=vcenter,
                            **c,
                            ssl_verify=False,
                            ignore_weak_ssl=True
                        )
                        vcenter_pool.append(cim)
                        process_pool.append(mp(target=main,
                                               kwargs={'cim': cim,
                                                       'influxq': iq,
                                                       'datadogq': dq
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
                        v.logout()
                    break
                logger.exception(f'Exception: {e} \n Args: {e.args}')
                start_main = True
                time.sleep(1)
                for v in vcenter_pool:
                    v.logout()
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
            v.logout()
        sys.exit(-1)
    except BaseException as e:
        if isinstance(e, SystemExit):
            logging.info(f'Agent exiting..')
            logging.info(f'Process pool terminating..')
            for proc in proc_pool:
                proc.terminate()
            for v in vcenter_pool:
                v.logout()
        else:
            logger.exception(f'Exception: {e} \n Args: {e.args}')
