"""
WSGI config for collector project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/howto/deployment/wsgi/
"""

import os, sys, platform
from django.core.wsgi import get_wsgi_application


if sys.version_info[0] < 3:
        from ConfigParser import ConfigParser
elif sys.version_info[0] == 3:
        from configparser import ConfigParser


# Retrieve and set script arguments for use throughout
parser = ConfigParser()

args = {}
config_filepath = None
if platform.system() == 'Windows':  # DEBUG Purposes only, production should be ran from linux
	if os.path.isfile('C:\\TEMP\\tmp\\metrics.conf'):
		config_filepath = 'C:\\TEMP\\tmp\\metrics.conf'
	else:
		raise "Unable to locate config file /etc/metrics/metrics.conf"
elif platform.system() == 'Linux':
	if os.path.isfile('/etc/metrics/metrics.conf'):
		config_filepath = '/etc/metrics/metrics.conf'
	else:
		raise "Unable to locate config file /etc/metrics/metrics.conf"

parser.read(config_filepath)

# [API]
api_path = parser.get('api', 'workingdirectory')
api_path = api_path.strip(' ').rstrip('/')

sys.path.append(api_path)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "collector.settings")

application = get_wsgi_application()

