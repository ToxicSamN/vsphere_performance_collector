# vsphere_performance_collector
Performance collector for VMs and ESXi hosts

## Collector
The metrics collectors will collect performance data from vcenter for all VMs and ESXi hosts. This is done on Linux RHEL7 and python 3.6.4 and sendign the data to a Telegraf/InfluxDB server. There is also a Django REST API for controlling how many objects each collector is collecting on.

A Collector group consists of a minimum:
1x Controller/Collector ( API )
If Needed : Additional Collectors ( Metric Collectors )

A collector group can ONLY collect on a single vCenter and cannot be used across multiple vCenters and can ONLY have 1 Controller


## How Does It Work (High Level)
The collectors work by dividing the total number of VMs or ESXi hosts in vCenter by the number of collectors collecting on that vCenter. So as the number of collectors increase, the number of objects collected reduce per collector, thus reducig the amount of time to collect the data. The number of servers collecting on a vCenter is controlled by the controller via API calls. As a new controller comes online it registers with the controller defined in the /etc/metrics/metrics.conf file. Each time the collection code is executed it will query the API for total groups and which group that collector is responsible for.

The code will pull all managedObjects of type VirtualMachine or HostSystem and then perform the math to determine which entities it is responsible for based on the assigned group. It will then create a new thread pool of 50 parallel threads and divide the entities it is responsible for into those 50 threads. Then it queries the performanceManager for all of those entities at once pulling 5 minutes of data at 20 second intervals, or 15 samples, and then parses through each entity and metric to formulate the JSON that gets sent to influxDB.

This is a multi threaded operation and not multi-processor operation due to having to reconnect to vCenter for each process vs being able to use the same single vCenter connection for all threads.

### NOTE/TODO:

It may be possible to gain additional efficiency by having a single collector collect on multiple groups of managedObjects. Instead of only collecting one group of VMs and one group of ESXi per collector, maybe 3 or 4 groups per collector is appropriate. The concern will be the number of processing threads opening. The bulk of this is when sending influxdb data to telegraf (itself) in which it is possible( at this scale) that 6000-10000 threads could be opened up and so some serious testing would need to be done. 

Create a central API controller instead of having a separate controller per group. This would allow a single place to query and determine what nodes are collecting on which vCenter as well as easily shift a  controller from one vcenter to another.

Dividing the duties out into multiple processes would be beneficial. Having the query in 1 process, the parsing in another process and the InfluxDB submission in a 3rd process all using multiprocessing queues to pass data between the processes. This would be a major rewrite to handle this.

Need to further reduce teh code from a single file to a module based approach and leaving the main function to utilize the other modules.

## OS Requirements:
Controllers/Collectors: 4 CPU, 8 GB memory
3rd Hard Disk of size 20GB
1 NIC - Preferably on the same vlan as vcenter, but this is not a requirement as long as firewall rules are properly configured

RHEL7 or CentOS7
Chef-Recipe: ucg-mgmt or some other configuration that will allow sudo for a particular group and service account
Apache (httpd)
Python 3.6.4
GIT repo (this can be internal or internet based, as long as each collector can access the git repo

## Firewall Requirements:
Source        Destination         Ports
Collector     Controller          tcp-80, tcp-443, tcp-8080, tcp-8443
Collector     vCenter             tcp-443
Collector     Telegraf/InfluxDB   tcp-8086, tcp-8186
Telegraf      InfluxDB            tcp-8086, tcp-8186
Collector     Git Repo            tcp-22, tcp-80, tcp-443
Controller    Git Repo            tcp-22, tcp-80, tcp-443
