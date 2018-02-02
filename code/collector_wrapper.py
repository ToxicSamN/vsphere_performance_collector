import argparse
import atexit
import sys, os, subprocess
import threading
import re
import ssl
import platform
import uuid
import json
import requests
import time
from socket import gethostname
from datetime import datetime
from datetime import timedelta
from socket import gethostname
from xml.dom.minidom import parseString


# This has been tested with the following versions of software:
#     * Python 3.5 64 bit
#


class CustomObject(object):
    def __init__(self, property={}):
        for k, v in property.items():
            setattr(self, k, v)

    def add_property(self, property):
        for k, v in property.items():
            setattr(self, k, v)

    def remove_property(self, property_name):
        delattr(self, property_name)


def findXmlSection(dom, sectionName):
    """
    Not my own function, pulled from
    https://gist.github.com/willianantunes/c8e4ad230c30297c4a1b
    :param dom:
    :param sectionName:
    :return:
    """
    sections = dom.getElementsByTagName(sectionName)
    return sections[0]


def get_property_map(ovfEnv):
    """
    Not my own function, pulled from
    https://gist.github.com/willianantunes/c8e4ad230c30297c4a1b
    :param ovfEnv:
    :return:
    """
    dom = parseString(ovfEnv)
    section = findXmlSection(dom, "PropertySection")
    propertyMap = {}
    for property in section.getElementsByTagName("Property"):
        key = property.getAttribute("oe:key")
        value = property.getAttribute("oe:value")
        propertyMap[key] = value
    dom.unlink()

    return propertyMap


def get_ovf_environment():
    """
    Not my own function, pulled from
    https://gist.github.com/willianantunes/c8e4ad230c30297c4a1b
    :return:
    """
    ovfEnv = subprocess.Popen("vmtoolsd --cmd 'info-get guestinfo.ovfEnv'", shell=True,
                              stdout=subprocess.PIPE).stdout.read()
    return get_property_map(ovfEnv)


def get_uuid():
    """
    Very specific to the collector VM itself. If the Collector VM OS changes or NIC changes then this becomes obsoltete
    This gets the UUID from the network configuration file
    :return:
    """
    try:
        with open('/etc/sysconfig/network-scripts/ifcfg-ens192', 'r') as file:
        #with open('C:\\TEMP\\tmp\\ifcfg-ens192', 'r') as file:
            lines = file.readlines()
            file.close()

        # using the regex of UUID= search throught the lines finding the line that matches this regex
        #  this will be returned int he form of UUID=12345-678-9012 and we want just the numbers not the UUID portion
        rex = re.compile('UUID=.')
        uuid_line = [line.strip('\n') for line in lines if re.match(rex, line)]
        if len(uuid_line) > 0:
            uuid_line = uuid_line[0]
        else:
            uuid_line = None

        # strip off the UUID= by splitting the line and pulling the second item
        if uuid_line is not None:
            return uuid_line.split('=')[1]
        else: return None
    except:
        raise


def responseok(response):
    """

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


def get_group_info(controller, uuid):
    """

    :param controller:
    :param uuid:
    :return:
    """
    collector_url = str('http://'+controller+':8080/api/collector/')
    group_url = str('http://' + controller + ':8080/api/group/' + uuid + '/')
    totalgroups_url = str('http://' + controller + ':8080/api/totalgroups/1/')

    groupinfo = {'Group': None, 'TotalGroups': None, 'TotalServerGroups': None}

    try:
        api_response = requests.get(group_url)
        if responseok(api_response):
            groupinfo['Group'] = api_response.json()['group']

        api_response = requests.get(totalgroups_url)
        if responseok(api_response):
            groupinfo['TotalGroups'] = api_response.json()['totalgroups']

        api_response = requests.get(collector_url)
        if responseok(api_response):
            groupinfo['TotalServerGroups'] = len(api_response.json())

    except:
        groupinfo = None
        pass

    return groupinfo


def get_ipaddress():
    """
    Sepecific to linux only, retrieve the IP address
    :return:
    """
    status = subprocess.Popen('sudo ip addr show', shell=True, stdout=subprocess.PIPE).stdout.read()
    status = status.decode()

    ip_line = [s for s in status.split('\n') if
               s.find(str('inet 10.')) != -1 or s.find(str('inet 172.')) != -1 or s.find(
                   str('inet 192.168.')) != -1][0]
    ip = [s for s in ip_line.split(' ') if
          s.find(str('10.')) != -1 or s.find(str('172.')) != -1 or s.find(str('192.168.')) != -1][0]

    return ip


def get_macaddress():
    """
    Sepecific to linux only, retrieve the MAC address
    :return:
    """
    status = subprocess.Popen('sudo ip addr show', shell=True, stdout=subprocess.PIPE).stdout.read()
    status = status.decode()

    mac_line = [s for s in status.split('\n') if s.find(str('link/ether 00:50:56')) != -1][0]
    mac = [s for s in mac_line.split(' ') if s.find(str('00:50:56')) != -1][0]

    return mac


def submit_server_info(args):
    """
    Send the server information to the API being hosted by the controller
    :param args:
    :return:
    """
    # POST URL has no trailing '/'
    c_url = 'http://' + str(args.ControllerIP) + ':8080/api/collector/'
    g_url = 'http://' + str(args.ControllerIP) + ':8080/api/groups/' + get_uuid() + '/'
    t_url = 'http://' + str(args.ControllerIP) + ':8080/api/totalgroups/1/'

    if args.IPAddress:
        ip = args.IPAddress
    else:
        # get IP from ip addr show
        ip = get_ipaddress()

    api_response = requests.post(url=c_url,
                                 json={'uuid': str(get_uuid()),
                                       'role': args.Role.lower(),
                                       'hostname': args.Hostname,
                                       'ip': ip,
                                       'mac': get_macaddress(),
                                       }
                                 )
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


def check_manifests():
    # since these scripts are already written then let's use the subprocess module to run these scripts
    status = subprocess.Popen('sudo /usr/local/bin/python3.6 /ucg/heartbeat/check_manifest.py', shell=True,
                              stdout=subprocess.PIPE).stdout.read()
    status = status.decode()
    return status


def check_services():
    # since these scripts are already written then let's use the subprocess module to run these scripts
    status = subprocess.Popen('sudo /usr/local/bin/python3.6 /ucg/heartbeat/check_services.py', shell=True,
                              stdout=subprocess.PIPE).stdout.read()
    status = status.decode()
    return status


def get_args():
    """
    Retrieve script arguments
    """
    ovf_env = get_ovf_environment()
    args = CustomObject()
    args.add_property({'Role': ovf_env['_1_Role']})
    args.add_property({'Hostname': ovf_env['_2_Hostname']})
    args.add_property({'ControllerIP': ovf_env['_3_Controller_IP']})
    args.add_property({'TelegrafIP': ovf_env['_3_Telegraf_IP']})
    args.add_property({'IPAddress': ovf_env['_4_IP_Address']})
    args.add_property({'SubnetMask': ovf_env['_5_Subnet_Mask']})
    args.add_property({'DefaultGateway': ovf_env['_6_Default_Gateway']})
    args.add_property({'VCIP': ovf_env['_7_VC_IP']})
    if args.VCIP:
        args.add_property({'vCenterIP': args.VCIP})
    else:
        args.add_property({'vCenterIP': ovf_env['vCenter']})
    args.add_property({'UUID': get_uuid()})
    args.add_property({'CurrentHostname': gethostname().strip('.ucgmetrics')})
    groupinfo = get_group_info(controller=args.ControllerIP, uuid=args.UUID)
    if groupinfo:
        args.add_property(groupinfo)

    return args


def main():
    """
    This would be the Main program execution
    """
    args = get_args()

    # COLLECTOR
    if args.Role == 'Collector':
    # check api for server info, if not then resubmit :
    #     this can be done by looking at if the parameter  args.Group parameter  exists
        if not hasattr(args, 'Group'):  # API hasn't been updated with the server information
            submit_server_info(args)
            args = get_args()

    # check for new manifests file and python files  : check_manifest.py
        check_manifests()

    # check that all services are enabled and running : check_services.py
        check_services()

    # CONTROLLER
    if args.Role == 'Controller':
        # check for new manifests file and python files  : check_manifest.py
        check_manifests()

        # check that all services are enabled and running : check_services.py
        check_services()

    return 0


if __name__ == '__main__':

    # infinite loop by design, pausing for 10 seconds
    #  this will be ran as a service
    while True:
        try:
            main()
        except:
            pass
        time.sleep(5)


