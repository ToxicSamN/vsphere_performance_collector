#!/bin/bash
#Launch the get_vm_metrics.py script 

cd /u01/git_repo/ucgmetrics_scripts
source metrics_collection/bin/activate
cd /u01/git_repo/ucgmetrics_scripts/metrics_collection

COMMAND="python code/get_metrics.py --collector-type VM"
	
RETURN=$($COMMAND)
