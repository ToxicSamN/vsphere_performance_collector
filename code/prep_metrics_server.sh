#!/bin/bash
# Prepare the metrics servers with the basic standard configurations

# Need to setup the 3rd hard disk using LVM
#  You should verify that /dev/sdc is the correct device for your 3rd hard disk before continuing
sudo pvcreate /dev/sdc
sudo vgcreate vg01 /dev/sdc
sudo lvcreate -l 100%FREE -n vol01 vg01
sudo mkdir /u01
sudo mkfs.xfs -L /u01 /dev/vg01/vol01
 
ISMOUNTED=$(mount | grep "/u01")
if [ -z "$ISMOUNTED" ]
then
	# Now you will need to edit the /etc/fstab file paste this line at the end
	# /dev/vg01/vol01 /u01    xfs     defaults        0 0
	sudo printf "/dev/vg01/vol01 /u01\txfs\tdefaults\t0 0\n" | sudo tee --append /etc/fstab
	sudo mount /u01
fi

ISMOUNTED=$(mount | grep "/u01")
if [ -z "$ISMOUNTED" ]
then
	echo "/u01 Device not mounted"
	exit
fi

# Create all of the directories
sudo mkdir /u01/tmp
sudo mkdir /u01/log
sudo mkdir /u01/git_repo
sudo mkdir /u01/api
sudo mkdir /u01/api/apache
sudo mkdir /u01/api/run
sudo mkdir /etc/metrics
  
# Setup the permissions and owner for smpadmins (Cig unix group)
sudo chown -R :smpadmin /u01
sudo chmod 674 -R /u01
sudo chmod 777 -R /u01/tmp
sudo chmod 777 -R /u01/log

# Replace the <XID> with your username, Do Not Copy and Paste these lines,
#  they will not work
cd /u01/git_repo
git clone https://$USER@git.nordstrom.net/scm/ucg/ucgmetrics_scripts.git
git clone https://$USER@git.nordstrom.net/scm/ucg/ucg_secure.git

# Copy all of the Configuration and Daemon files to their forever home
sudo cp -f /u01/git_repo/ucgmetrics_scripts/metrics_collection/metrics.conf /etc/metrics/
sudo cp -f /u01/git_repo/ucgmetrics_scripts/metrics_collection/services/get-vmmetrics.service /etc/systemd/system/
sudo cp -f /u01/git_repo/ucgmetrics_scripts/metrics_collection/services/get-esxmetrics.service /etc/systemd/system/
sudo cp -f /u01/git_repo/ucgmetrics_scripts/metrics_collection/services/write-influxdb.service /etc/systemd/system/
sudo cp -f /u01/git_repo/ucgmetrics_scripts/metrics_collection/services/startuplast.target /etc/systemd/system/
sudo cp -f /u01/git_repo/ucgmetrics_scripts/metrics_collection/services/django.conf /etc/httpd/conf.d/
sudo cp -Rf /u01/git_repo/ucgmetrics_scripts/metrics_collection/api/_collector/ /u01/api/collector
sudo cp -f /u01/api/collector/collector/wsgi.py /u01/api/apache/


# set the permissions for the API structure
sudo chown -R :smpadmin /u01/api
sudo chmod 674 -R /u01/api
sudo chown apache:smpadmin /u01/api/collector
sudo chown apache:smpadmin /u01/api/collector/db.sqlite3

sudo mkdir /u01/api/key
sudo chown -R root:root /u01/api/key 
sudo chmod -R 644 /u01/api/key

cd /u01/git_repo/ucgmetrics_scripts
source metrics_collection/bin/activate
cd /u01/git_repo/ucgmetrics_scripts/metrics_collection

