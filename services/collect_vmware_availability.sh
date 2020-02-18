#!/bin/bash
#Launch the collect_vmware_availability.py script

cd /u01/code/vsphere_performance_collector
source venv/bin/activate
export PYTHONPATH=/u01/code/vsphere_performance_collector
echo $PYTHONPATH
cd /u01/code/vsphere_performance_collector/vspherecollector

COMMAND="python collect_vmware_availability.py --collector-type VCSERVICES --config-file /etc/metrics/vc_metrics.conf"
	
RETURN=$($COMMAND)
