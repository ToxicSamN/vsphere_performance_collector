# /api/models.py

from django.db import models


class Group(models.Model):
    """This is the class for the Group model"""
    uuid = models.CharField(max_length=200, blank=False, unique=True)
    group = models.CharField(max_length=32)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        """Return a human readable representation of the model instance"""
        return "{}\n{}\n".format(self.uuid, self.group)

    def __unicode__(self):
        return self.group


class TotalGroups(models.Model):
    """This is the class for the TotalGroups model"""
    totalgroups = models.CharField(max_length=4)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        """Return a human readable representation of the model instance"""
        return self.totalgroups

    def __unicode__(self):
        return self.totalgroups

class Collector(models.Model):
    """This is the class for the collector model"""
    hostname = models.CharField(max_length=64, unique=True)
    role = models.CharField(max_length=32, blank=True)
    uuid = models.CharField(max_length=200, blank=False, unique=True)
    ip = models.CharField(max_length=15, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        """Return a human readable representation of the model instance"""

        return "HOSTNAME: {}\n" \
               "UUID: {}\n" \
               "ROLE: {}\n" \
               "IPADDR: {}\n" \
               "TOTALGROUPS: {}\n" \
               "CREATED: {}\n" \
               "MODIFIED: {}".format(self.hostname,
                                     self.uuid,
                                     self.role,
                                     self.ip,
                                     self.date_created,
                                     self.date_modified,
                                     )

