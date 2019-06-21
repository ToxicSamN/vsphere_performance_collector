
import argparse
from configparser import ConfigParser
from configparser import NoOptionError
from pycrypt.encryption import AESCipher


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
                            required=False, action='store',
                            help='identifies what moRef type to collect on (HOST, VM)')
        parser.add_argument('-c', '--config-file', default='/etc/metrics/metrics.conf',
                            required=False, action='store',
                            help='identifies location of the config file')
        parser.add_argument('-t', '--threshold', default=295,
                            required=False, action='store',
                            help='threshold for rerunning the code')
        cmd_args = parser.parse_args()

        self.DEBUG = cmd_args.debug
        self.MOREF_TYPE = cmd_args.collector_type
        self.running_threshold = cmd_args.threshold

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
            if debug_check.lower() == 'true':
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
