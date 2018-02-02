# /api/serializers.py

from rest_framework import status
from rest_framework import serializers
from rest_framework.response import Response
from .models import Collector, TotalGroups, Group


class GroupSerializer(serializers.ModelSerializer):
    """Serializer to map the Model instance into JSON format."""

    class Meta:
        """Map this serializer to a model and their fields."""
        model = Group
        fields = ('uuid', 'group')
        read_only_fields = ('date_created', 'date_modified')


class TotalGroupsSerializer(serializers.ModelSerializer):
    """Serializer to map the Model instance into JSON format."""

    class Meta:
        """Map this serializer to a model and their fields."""
        model = TotalGroups
        fields = ('id', 'totalgroups', 'date_created', 'date_modified')
        read_only_fields = ('date_created', 'date_modified')



class CollectorSerializer(serializers.ModelSerializer):
    """Serializer to map the Model instance into JSON format."""

    class Meta:
        """Map this serializer to a model and their fields."""
        model = Collector
        fields = ('hostname', 'role', 'uuid', 'ip', 'date_created', 'date_modified',)
        read_only_fields = ('date_created', 'date_modified',)



