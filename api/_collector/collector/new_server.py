import requests
from rest_framework import status
from rest_framework.response import Response
from .models import Group, TotalGroups, Collector


class launch_new_server(object):
    """ This is a class for handling a new server registering with the controller's api"""

    def __init__(self, data):
        self.requestdata = data
        self.local_url = 'http://127.0.0.1:8080/api/'
        self.uuid = data["uuid"]
        self.hostname = data["hostname"]
        self.role = data["role"]
        self.ip = data["ip"]
        self.mac = data["mac"]
        self.group = Group.objects.filter(uuid=self.uuid)
        self.existing_server = Collector.objects.filter(uuid=self.uuid)
        self.totalgroups = TotalGroups.objects.filter(id=1)
        self.response = None


    def start(self):
        """ start """

        # Default RESPONSE will be 400 BAD REQUEST
        self.response = Response(['HTTP 400 BAD REQUEST. Server already exists', self.requestdata],
                                 status=status.HTTP_400_BAD_REQUEST)

        if not self.validate_data():  # There are NULL values where there shouldn't be
            return Response(['HTTP 400 BAD REQUEST. Required fields are NULL', self.requestdata],
                            status=status.HTTP_400_BAD_REQUEST)

        if not self.existing_server:

            if self.group:
                # there is already a group entry for this UUID, so we will leave this entry alone and only update
                #    the Collector model
                cmo = Collector.objects.create(uuid=self.uuid,
                                               hostname=self.hostname,
                                               role=self.role,
                                               ip=self.ip,
                                               mac=self.mac)
                self.existing_server = Collector.objects.filter(uuid=self.uuid)

                self.response = Response(['HTTP 200 OK', self.requestdata], status=status.HTTP_200_OK)

            else:   # existing group entry doesn't exist in the Group model, so let's create one
                    #   as well as create the Collector object and update the TotalGroups model

                # first check self.totalgroups
                if not self.totalgroups:  # there does not exist a TotalGroups entry, so we will create an initial one
                    tmo = TotalGroups.objects.create(totalgroups='0')

                self.totalgroups = TotalGroups.objects.filter(id=1)

                # create the group_info string in the format of W:X:Y:Z (ex. 1:2:3:4)
                group_info = ''

                # range needs to be definded as totalgroups +1 as the starting number and the end need to be +5
                #    because we are hard coding the group size as +4 and we need to go +1 more than that due to how
                #    range works.
                for x in range(int(self.totalgroups[0].totalgroups) + 1, int(self.totalgroups[0].totalgroups) + 5):
                    group_info = group_info + str(x) + ':'
                group_info = group_info.strip(':')

                gmo = Group.objects.create(uuid=self.uuid, group=group_info)
                self.group = Group.objects.filter(uuid=self.uuid)

                tmo = TotalGroups.objects.update(id=1, totalgroups=str(int(self.totalgroups[0].totalgroups) + 4))
                self.totalgroups = TotalGroups.objects.filter(id=1)

                cmo = Collector.objects.create(uuid=self.uuid, hostname=self.hostname, role=self.role, ip=self.ip, mac=self.mac)
                self.existing_server = Collector.objects.filter(uuid=self.uuid)

                self.response = Response(['HTTP 200 OK', self.requestdata], status=status.HTTP_200_OK)

        return self.response


    def validate_data(self):
        """ This function is to validate whether there is valid data before updating the models"""
        collector_fields = Collector._meta.get_fields()
        for field in collector_fields:
            # validate that the Model fields that are required or cannot be null are in fact not null
            if not (field._unique or field.primary_key or not field.null) and not \
                    self.__dict__[field.name]:
                return False
        return True









