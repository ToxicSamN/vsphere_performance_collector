#!/bin/bash
#Write influx Data from influxdb-write.service in /etc/systemd/system/
#Launch the write_influx_data.py script

cd /u01/git_repo/ucgmetrics_scripts
source metrics_collection/bin/activate
cd /u01/git_repo/ucgmetrics_scripts/metrics_collection

COMMAND="python code/write_influx_data.py"

# this script is an infinite loop and will never end until the server is shutdown
RETURN=$($COMMAND)
sleep 1

