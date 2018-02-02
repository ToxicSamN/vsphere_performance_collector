import sys
from shutil import copy2


if __name__ == '__main__':

    host_name = str(sys.argv[1])
    host_name = host_name.split('.')[0]
    tmp = host_name.split('-')
    prefix, suffix = '', ''
    for x in range(0, len(tmp)):
        if x == 0:
            prefix = tmp[0]
        elif x == (len(tmp)-1):
            suffix = tmp[x]
        else:
            if tmp[x] != 'controller' and tmp[x] != 'telegraf' and tmp[x] != 'influxdb':
                prefix = prefix + "-" + tmp[x]
    for r in range(1, 10):
        suffix = suffix.strip(str(r))
    suffix = suffix + '0'
    name = prefix + '-' + suffix

    line = "UUID=,HOSTNAME=" + name + ",IP=,MAC=00:00:00:00:00:00,SERVERGROUP=0,GROUP=0"
    with open('/ucg/heartbeat/hosts_info', 'w') as f:
        f.write(line+'\n')
        f.close()