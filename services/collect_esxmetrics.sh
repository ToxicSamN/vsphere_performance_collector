#!/bin/bash
#Launch the collect_metrics.py script

cd /u01/code/vsphere_performance_collector
source venv/bin/activate
export PYTHONPATH=/u01/code/vsphere_performance_collector
cd /u01/code/vsphere_performance_collector/vspherecollector

COMMAND="python collect_metrics.py --collector-type HOST --config-file /etc/metrics/metrics.conf"
	
RETURN=$($COMMAND)
