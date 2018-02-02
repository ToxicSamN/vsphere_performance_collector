import sys, os, subprocess
import re
import platform
import pysftp
from shutil import copy2
from xml.dom.minidom import parseString
from socket import gethostname


# This has been tested with the following versions of software:
#     * Python 3.5 64 bit
#     * pyVmomi 6.5
#     * influxdb 1.2.4-1
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
    sections = dom.getElementsByTagName(sectionName)
    return sections[0]


def get_property_map(ovfEnv):
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
    ovfEnv = subprocess.Popen("vmtoolsd --cmd 'info-get guestinfo.ovfEnv'", shell=True,
                              stdout=subprocess.PIPE).stdout.read()
    return get_property_map(ovfEnv)


def get_uuid():
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


def check_service(service):
    # this function is Linux specific and specific to systemctl
    try:
        status = subprocess.Popen('systemctl status ' + service, shell=True, stdout=subprocess.PIPE).stdout.read()
        status = status.decode()

        enabled = [s for s in status.split('\n') if s.find(str('/' + service + '.service; enabled;')) != -1]
        running = [s for s in status.split('\n') if s.find(str('Active: active (running)')) != -1]

        if not enabled:
            subprocess.Popen('systemctl enable ' + service, shell=True, stdout=subprocess.PIPE)
            subprocess.Popen('systemctl start ' + service, shell=True, stdout=subprocess.PIPE)

        if enabled and not running:
            subprocess.Popen('systemctl start ' + service, shell=True, stdout=subprocess.PIPE)

        return True
    except:
        return False


def get_args():
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

    return args

if __name__ == '__main__':

    args = get_args()

    if args.Role == 'Collector':
        services = ['influxdb-write',
                    'get-vm-metrics-1',
                    'get-vm-metrics-2',
                    'get-vm-metrics-3',
                    'get-vm-metrics-4',
                    'get-vm-metrics-5',
                    'get-vm-metrics-6',
                    'collector-wrapper']

        for svc in services:
            check_service(svc)
        
    elif args.Role == 'Controller':
        # enable and run httpd
        check_service('httpd')
        check_service('collector-wrapper')
