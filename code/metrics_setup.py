
import sys, os, subprocess
import json
import logging
import logging.config
import logging.handlers
import platform
import requests
import multiprocessing
from socket import gethostname
loggers = {}

# This has been tested with the following versions of software:
#     * Python 3.5 64 bit


class UcgCryptoKey(object):
    # This is a custom class for obtaining the crypto key for the credentials.
    #    TODO:
    #        Option 1: This should be reading from a GIT repo for the crypto key instead of local filesystem
    #        Option 2: devise a setup in which the crypto key is encrypted with RSA Key-pair and stored in the api
    #          database. When requesting the crypto key from the api the api will use RSA key-pair to decrypt and
    #          re-encrypt to send back. This eliminates filesystems storage completely.

    

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
    # This class is used to create or get a credential set.
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
            secret_code=UcgCryptoKey(crypto_path).crypto_key
        else:
            secret_code=UcgCryptoKey().crypto_key
        
        tmp = UcgEncryption()
        tmp.decrypt(private_key, encrypted_password, secret_code=secret_code)
        
        return tmp.decrypted_message


class UcgEncryption(object):

    # This class does the heavy lifting of encrypting string, decrypting strings, generating RSA Key-pair, or pulling the
    # MD5 hash of a file. There is a default secret_code, but shouldn't have to tell you ... never use the default outside
    # of development.

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


class CustomObject(object):
    def __init__(self, property={}):
        for k, v in property.items():
            setattr(self, k, v)

    def add_property(self, property):
        for k, v in property.items():
            setattr(self, k, v)

    def remove_property(self, property_name):
        delattr(self, property_name)


def responseok(response):
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
    # This will query the API the controller is hosting to parse out the group information
    # :param controller:
    # :param uuid:
    # :return:

    collector_url = str('http://' + controller + ':8080/api/collector/')  # get all collectors
    group_url = str('http://' + controller + ':8080/api/collector/groups/' + uuid + '/')  # get the group for this uuid

    groupinfo = {'Group': None, 'TotalGroups': None}

    try:
        api_response = requests.get(group_url)
        if responseok(api_response):
            groupinfo['Group'] = api_response.json()['group']

        api_response = requests.get(collector_url)
        if responseok(api_response):
            groupinfo['TotalGroups'] = len(api_response.json())

        return groupinfo
    except:
        groupinfo = None
        return groupinfo


def write_lines(file_path, input_object):
    str_format = ''
    if isinstance(input_object, list):
        for i in input_object:
            str_format = str_format + '{}\n'
    elif isinstance(input_object, str):
        str_format = '{}\n'
        input_object = [input_object]

    try:
        with open(file_path, 'w') as f:
            f.writelines(str_format.format(*input_object))
            f.close()
        return 0
    except:
        return 1


def submit_server_info(args):
    
    logger = get_logger('submit_server_info')
    
    logger.info('Args: {}'.format(args))
    # POST URL has no trailing '/'
    c_url = 'http://' + str(args['ControllerIP']) + ':8080/api/collector/'
    g_url = 'http://' + str(args['ControllerIP']) + ':8080/api/groups/'+gethostname().lower() +'/'

    ip = get_ipaddress()
    logger.info('URL: {}, UUID/Hostname: {}, role: {}, IP: {}'.format(c_url, str(gethostname().lower()), args['role'].lower(), ip))
    api_response = requests.post(url=c_url,
                                 json={'uuid': str(gethostname().lower()),
                                       'role': args['role'].lower(),
                                       'hostname': str(gethostname().lower()),
                                       'ip': ip,
                                       }
                                 )
    logger.info('API Response Code: {}, Response Msg: {}'.format(api_response.status_code, api_response.content.decode()))
    if api_response.content.decode().find('Unable to update Groups table') != -1:  # Failed to update Groups Table
        g_res = requests.get(g_url)
        if responseok(g_res):
            g_res = requests.delete(g_url)
            if responseok(g_res):
                api_response = submit_server_info(args)
                return api_response
            else:
                return g_res

    return api_response


def get_ipaddress():
    status = subprocess.Popen('ip addr show', shell=True, stdout=subprocess.PIPE).stdout.read()
    status = status.decode()

    ip_line = [s for s in status.split('\n') if
               s.find(str('inet 10.')) != -1 or
               s.find(str('inet 172.')) != -1 or
               s.find(str('inet 192.168.')) != -1][0]
    ip = [s for s in ip_line.split(' ') if
          s.find(str('10.')) != -1 or
          s.find(str('172.')) != -1 or
          s.find(str('192.168.')) != -1][0]

    return ip.split('/')[0]


def get_args():

    import argparse
    from configparser import ConfigParser
    global DEBUG_MODE
    global LOG_SIZE
    global LOG_DIR
    global MAX_KEEP    

    # Retrieve and set script arguments for use throughout
    parser = argparse.ArgumentParser(description="Deploy a new VM Performance Collector VM.")
    parser.add_argument('-oppvmwre', '--password',
                        required=True, action='store',
                        help='Service Account password to encrypt')     
    
    parser.add_argument('-debug', '--debug',
                        required=False, action='store_true',
                        help='Used for Debug level information')    
    cmd_args = parser.parse_args()
    parser = ConfigParser()

    DEBUG_MODE = cmd_args.debug

    args = {'pwd': cmd_args.password}
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
    
    # [API]
    args.update({'api_path': str(parser.get('api', 'WorkingDirectory')).rstrip('/')})
    
    # [METRICS]
    args.update({'ControllerIP': parser.get('metrics', 'ControllerIP')})

    groupinfo = get_group_info(controller=args['ControllerIP'], uuid=gethostname().lower())
    if groupinfo:
        args.update(groupinfo)

    return args


def get_logger(name):
    
    global DEBUG_MODE
    global LOG_LEVEL
    global LOG_SIZE
    global LOG_DIR
    global MAX_KEEP    
    global loggers
    
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
        dfh = logging.handlers.RotatingFileHandler(LOG_DIR + '/metrics_setup.log', 
                                                       mode='a', 
                                                       maxBytes=int(logsize), 
                                                       backupCount=int(MAX_KEEP), 
                                                       encoding='utf8', 
                                                       delay=False)
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(formatter)
        
        lfh = logging.handlers.RotatingFileHandler(LOG_DIR + '/metrics_setup.log', 
                                                       mode='a', 
                                                       maxBytes=int(logsize), 
                                                       backupCount=int(MAX_KEEP), 
                                                       encoding='utf8', 
                                                       delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(formatter)
        
        efh = logging.handlers.RotatingFileHandler(LOG_DIR + '/metrics_setup_error.log', 
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
    This would be the Main program execution
    """     
    args = get_args()
    
    logger = get_logger('main')

    logger.info('ServerType: {}'.format(args['role']))
    
    # Generate RSA Keypair and encrypt password
    crypto_path = args['secdir']+'/crypto'
    pkey_path = args['secdir']+'/privkey'
    pubkey_path = args['secdir']+'/pubkey'
    with open(crypto_path, 'wb') as crypto_out:
        crypto_out.write(os.urandom(1048576))
        crypto_out.close()
    enc = UcgEncryption()
    crypto_key = UcgCryptoKey(crypto_path).crypto_key
    enc.generate_rsa_key_pair(public_file=pubkey_path, private_file=pkey_path, secret_code=crypto_key)
    
    cred = UcgCredential('vCenter')
    cred.new(pubkey_path, clear_password=args['pwd'])
    with open(args['secdir']+'/secure', 'wb') as f:
        f.write(cred.encrypted_password)
        f.close()
    cred=None
    args['pwd'] = None

    try:
        if args['role'].lower() == 'CONFIG_MODE':
            return 0

        # CONTROLLER
        if args['role'].lower() == 'controller' or args['role'].lower() == 'both':
            
            # copy the contents of args['bin]/api/_collector/* to args['api_path']
            if not os.path.isdir(args['api_path']):
                # create the directory for api_path
                os.makedirs(args['api_path'])

            if not os.path.isfile(args['api_path'] + '/db.sqlite3'):
                subprocess.Popen(str('sudo cp -Rf '+args['bin']+'/api/_collector/* '+args['api_path']+'/'), shell=True, stdout=subprocess.PIPE)
            
            # change the collector API django setting.py file :
            #  Modify the AllowedHosts = [] to ALLOWED_HOSTS = ['localhost', '127.0.0.1', get_ipaddress()]
            # try:
            #     logger.info('Edit collector/settings.py : ALLOWED_HOSTS = []')
            #     with open(str(args['api_path'] + '/collector/settings.py'), 'r') as f_read:
            #         lines = f_read.readlines()
            #         f_read.close()
            #         logger.debug('Read Lines: {}'.format(lines))
            #     mod_contents = []
            #     for line in lines:
            #         if line.strip('\n') == 'ALLOWED_HOSTS = []':
            #             logger.debug('Found the appropriate line {}'.format(line.strip('\n')))
            #             line = "ALLOWED_HOSTS = ['localhost', '127.0.0.1', '" + get_ipaddress() + "']\n"
            #             logger.debug('Changing to  {}'.format(line.strip('\n')))
            #         if line.strip('\n') == 'DEBUG = True':
            #             logger.debug('Found the appropriate line {}'.format(line.strip('\n')))
            #             line = "DEBUG = False\n"
            #             logger.debug('Changing to  {}'.format(line.strip('\n')))
            #
            #         mod_contents += [line.strip('\n')]
            #     logger.info('Writing changes to collector/settings.py')
            #     write_lines(str(args['api_path'] + '/collector/settings.py'), mod_contents)
            #     logger.info('Writing changes to collector/settings.py SUCCESS')
            # except BaseException as e:
            #     logger.exception('Exception: {}, ARGS: {}'.format(e, e.args))

            # enable httpd service for the api (settings.py needs to be set before enabling httpd
            logger.info('Enable service httpd (Apache)')
            subprocess.Popen('sudo systemctl enable httpd', shell=True, stdout=subprocess.PIPE)
            logger.info('Starting service httpd (Apache)')
            subprocess.Popen('sudo systemctl start httpd', shell=True, stdout=subprocess.PIPE)

        # COLLECTOR
        if args['role'].lower() == 'collector' or args['role'].lower() == 'both':
            # submit server info to api
            args.update({'IPAddress': get_ipaddress()})
            submit_server_info(args)
            args = get_args()

            # setup startuplast.target
            logger.info('Setting up startuplast.target')
            subprocess.Popen('sudo systemctl isolate startuplast.target', shell=True, stdout=subprocess.PIPE)
            subprocess.Popen(
                'sudo ln -sf /etc/systemd/system/startuplast.target /etc/systemd/system/default.target', shell=True,
                stdout=subprocess.PIPE)

            # enable get-metrics service
            logger.info('Enable service telegraf')
            subprocess.Popen('sudo systemctl enable telegraf', shell=True, stdout=subprocess.PIPE)
            logger.info('Starting service telegraf')
            subprocess.Popen('sudo systemctl start telegraf', shell=True, stdout=subprocess.PIPE)

            # enable get-metrics service
            logger.info('Enable service get-vmmetrics')
            subprocess.Popen('sudo systemctl enable get-vmmetrics', shell=True, stdout=subprocess.PIPE)
            logger.info('Starting service get-vmmetrics')
            subprocess.Popen('sudo systemctl start get-vmmetrics', shell=True, stdout=subprocess.PIPE)

            # enable get-metrics service
            logger.info('Enable service get-esxmetrics')
            subprocess.Popen('sudo systemctl enable get-esxmetrics', shell=True, stdout=subprocess.PIPE)
            logger.info('Starting service get-esxmetrics')
            subprocess.Popen('sudo systemctl start get-esxmetrics', shell=True, stdout=subprocess.PIPE)


        return 0
    except BaseException as e:
        logger.exception('Exception: {}, ARGS: {}'.format(e, e.args))


if __name__ == '__main__':
        
    # should be launched with sudo access
    args = get_args()
    
    main()
            
