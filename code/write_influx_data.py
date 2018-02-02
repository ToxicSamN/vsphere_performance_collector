
import sys, os, subprocess
import threading
import json
import platform
import requests
import logging
import logging.config
import time
from multiprocessing import Process as mp
from influxdb import InfluxDBClient
from datetime import datetime
loggers = {}

"""
    This script is used to write JSON data to influxdb.
    This is very specific to the VM Performance collector vms that are being used to collect VM performance data
    This script will read in all of the JSON files that were output by get_vm_metrics.py
"""


class InfluxDBThread(object):
    
    def __init__(self, data, influxdb_client, time_precision, file_path, db_env, pid, sindex, eindex):
        self.data = data
        self.influxdb_client = influxdb_client
        self.time_precision = time_precision
        self.file_path = file_path
        self.db_env = db_env
        self.pid = pid
        self.start_index = sindex
        self.end_index = eindex
        
    
# class InfluxDBThread (threading.Thread):
    # """
        # This class handles the influxdb writes. This is used for muti-threading the write-process
    # """
    # def __init__(self, threadID, name, json_series, influxdb_client, time_precision, file_path):
        # threading.Thread.__init__(self)
        # self.threadID = threadID
        # self.name = name
        # self.json_series = json_series
        # self.influxdb_client = influxdb_client
        # self.time_precision = time_precision
        # self.file_path = file_path
        # self.return_code = None

    # def run(self):
        # try:
            # self.return_code = self.influxdb_client.write_points(self.json_series, time_precision=self.time_precision)
        # except:
            # self.return_code = 'FAILED'
            # pass


class CustomObject(object):
    """
       Because I came from powershell I was really spoiled with New-Object PSObject
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


def run_thread_pool(func_args_array, pool_size = 2):
    from multiprocessing.dummy import Pool
    
    t_pool = Pool(pool_size)
    results = t_pool.map(send_influx, func_args_array)
    t_pool.close()
    t_pool.join()
    return results      

def run_mp_pool(func_args_array):
    from multiprocessing import Pool as mpool
    
    m_pool = mpool()
    results = m_pool.map(main, func_args_array)
    m_pool.close()
    m_pool.join()
    return results

def send_influx(influx_obj):
    """ Send te JSON data to InfluxDB """
    
    logger = get_logger(str('send_influx_p' + str(influx_obj.pid) + '_' + str(influx_obj.start_index) + ':' + str(influx_obj.end_index)))
    logger.debug('ARGS: {}'.format(influx_obj))
    
    try:
        logger.debug('Attempting to send InfluxDB data')
        tmp = influx_obj.influxdb_client.write_points("\n".join(influx_obj.data), time_precision=influx_obj.time_precision, protocol='line')
        logger.debug('Data sent to InfluxDB successfully')
        return {'env': influx_obj.db_env, 'filepath': influx_obj.file_path, 'return': True}
    except BaseException as e:
        logger.exception("Unable to Send InfluxData.")
        logger.error('Args: json_series {}, {}, {}, {}, {}, {}, {}, {}'.format(len(influx_obj.data), influx_obj.influxdb_client, influx_obj.time_precision, influx_obj.file_path, influx_obj.db_env, influx_obj.pid, influx_obj.start_index, influx_obj.end_index))
        return {'env': influx_obj.db_env, 'filepath': influx_obj.file_path, 'return': False}


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


def load_json(file_path):
    """
    Custom function for loading a json file
    :param file_path:
    :return:
    """
    logger = get_logger('load_json')

    json_data = None
    try:
        logger.info('Loading JSON file {}'.format(file_path))
        with open(file_path, 'r') as json_file:
            json_data = json.load(json_file)
            json_file.close()
            logging.debug('Reading JSON data \n{}'.format(json_data))
    except Exception as e:
        logger.exception('Failed to open file {}'.format(file_path))

    return json_data


def track_threads(threads, throttle_threads=2):
    """
    Custom thread tracker (instead of using ThreadPool) to control how many threads are running at a time
    :param threads:
    :param throttle_threads:
    :return:
    """
    all_threads = list(threads)
    idle_threads = list(threads)
    start_threads = []
    running_threads = []
    finish_threads = []
    running_thread_count = 1

    # loop through the threads to launch each one throttling to 3 threads
    #  this requires that the system running this code has a minimum of 4 threads available to use.
    while len(all_threads) != len(finish_threads):
        try:
            for t in idle_threads:
                if running_thread_count <= throttle_threads:
                    start_threads.append(t)
                    t.start()
                    idle_threads.remove(t)
                    running_thread_count += 1

            for t in [x for x in start_threads if x not in running_threads]:
                running_threads.append(t)
                t.join()
                start_threads.remove(t)

            for t in [x for x in running_threads if x not in finish_threads]:
                if not t.is_alive():
                    finish_threads.append(t)
                    running_threads.remove(t)
                    running_thread_count -= 1
                    if t.return_code != 'FAILED':
                        os.remove(t.file_path)
        except:
            pass

    return finish_threads


def get_args():

    import argparse
    from configparser import ConfigParser
    global DEBUG_MODE
    global LOG_SIZE
    global LOG_DIR
    global MAX_KEEP    

    # Retrieve and set script arguments for use throughout
    parser = argparse.ArgumentParser(description="Deploy a new VM Performance Collector VM.")
    parser.add_argument('-debug', '--debug',
                        required=False, action='store_true',
                        help='Used for Debug level information')    
    cmd_args = parser.parse_args()
    parser = ConfigParser()

    DEBUG_MODE = cmd_args.debug

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
    
    try:
        debug_check = parser.get('logging', 'Debug')
        if debug_check == 'True':
            DEBUG_MODE = True
    except:
        pass

    # [INFLUXDB]
    args.update({'TelegrafIP': parser.get('influxdb', 'TelegrafIP')})
    args.update({'npPort': parser.get('influxdb', 'nonprod_port')})
    args.update({'pPort': parser.get('influxdb', 'prod_port')})

    return args


def get_logger(name):
    
    global DEBUG_MODE
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
        
        lfh = logging.handlers.RotatingFileHandler(LOG_DIR + PATH_SEPARATOR + 'write_influxdb.log', 
                                                       mode='a', 
                                                       maxBytes=int(logsize), 
                                                       backupCount=int(MAX_KEEP), 
                                                       encoding='utf8', 
                                                       delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(formatter)
        
        efh = logging.handlers.RotatingFileHandler(LOG_DIR + PATH_SEPARATOR + 'write_influxdb_error.log', 
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



def main(func_args):
    # Send the performance data to influxDB
    file_name, pid = func_args
    args = get_args()
    
    main_logger = get_logger('main_p' + str(pid))

    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    main_logger.info(str('Started at ' + start_time))
    main_logger.info(str('Args: {}'.format(args)))

    prod_influx_client = InfluxDBClient(host=args['TelegrafIP'],  # args.TelegrafIP
                                        port=int(args['pPort']),  # 8186
                                        username='anonymous',
                                        password='anonymous',
                                        database='perf_stats',
                                        timeout=5,
                                        retries=1)
    
    group_size = 100000
    parallelism_thread_count = 100

    json_path = str(args['tmpdir']+'/')

    try:
        # files = os.listdir(json_path)
        pool_args = []
        # for file in files:
        #     if file.startswith("json.output."):
        json_load = load_json(json_path + file_name)
        start_index = 0
        if len(json_load) % group_size == 0:
            num_groups = int(len(json_load))
        else:
            num_groups = int(len(json_load) / group_size) + 1
        
        for group in range(1, num_groups+1):
            if group == num_groups:
                end_index = len(json_load)
                json_slice = json_load[start_index:end_index]
            else:
                end_index = (start_index + group_size) + 1
                json_slice = json_load[start_index:end_index]
            
            influx = InfluxDBThread(json_slice, prod_influx_client, 'n', (json_path + file_name), 'prod', pid, start_index, end_index)
            main_logger.info('Creating Pool_Args group: {}, numGroup: {},  s: {}, e: {}, tot: {}'.format(group, num_groups, start_index, end_index, len(json_load)))
            pool_args.append(influx)
            start_index += group_size + 1
        main_logger.info('Starting InfluxDB Writes in Multi-threaded parallelism')
        finish_threads = run_thread_pool(pool_args, pool_size=parallelism_thread_count - 1)
        
        for t in finish_threads:
            if t['return']:
                if os.path.isfile(t['filepath']):
                    main_logger.info('Removing the file {}'.format(t['filepath']))
                    try:
                        os.remove(t['filepath'])
                    except:
                        main_logger.exception('Failed to remove file {}.'.format(t['filepath']))

    except BaseException as e:
        main_logger.exception('Exception occurred but continuing script. Exception: {} : Args: {}'.format(e, e.args))
        pass
    
    return 0


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
            start_time = datetime.now()
            root_logger.info('Executing MAIN...')
            
            json_path = str(args['tmpdir']+'/')
            
            files = os.listdir(json_path)
            pool_args = []
            mp_count = 1
            #mp_pool = Pool()
            for file in files:
                if file.startswith("json.output."):
                    pool_args.append((file, mp_count))
                    mp_count = mp_count + 1
            #p = mp(target=main)
            #p.start()
            #p.join(300)
            run_mp_pool(pool_args)
            # if p.is_alive():
                # p.terminate()
                # root_logger.error(
                    # 'MAIN program running too long. Start Time: {}, End Time: {}'.format(start_time.ctime(),
                                                                                         # datetime.now().ctime()))
            
            root_logger.info('Execution Complete')
            end_time = datetime.now()
            time.sleep(5)
            error_count = 0

        except BaseException as e:
            root_logger.exception('Exception: {} \n Args: {}'.format(e, e.args))
            time.sleep(1)
            if error_count > 20:
                raise e
            else:
                error_count = error_count + 1
                pass


