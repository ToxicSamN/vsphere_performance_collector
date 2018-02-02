# /api/views.py

from rest_framework import generics
from .models import Collector, Group, TotalGroups
from .serializers import CollectorSerializer, GroupSerializer, TotalGroupsSerializer
from .new_server import launch_new_server


class GroupCreateView(generics.ListCreateAPIView):
    """This class defines the create behavior of our rest api"""

    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    lookup_field = 'uuid'


class GroupDetailsView(generics.RetrieveUpdateDestroyAPIView):
    """This class handles the http GET, PUT, and DELETE requests."""

    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    lookup_field = 'uuid'


class TotalGroupsCreateView(generics.ListCreateAPIView):
    """This class defines the create behavior of our rest api"""

    queryset = TotalGroups.objects.all()
    serializer_class = TotalGroupsSerializer

    """
        These are the default built-in definitions for generics.ListCreateAPIView
    """

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


class TotalGroupsDetailsView(generics.RetrieveUpdateDestroyAPIView):
    """This class handles the http GET, PUT, and DELETE requests."""

    queryset = TotalGroups.objects.all()
    serializer_class = TotalGroupsSerializer

    """ 
        These are the default built-in definitions for generics.RetrieveUpdateDestroyAPIView 
    """

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


class CollectorCreateView(generics.ListCreateAPIView):
    """This class defines the create behavior of our rest api"""

    queryset = Collector.objects.all()
    serializer_class = CollectorSerializer
    lookup_field = 'uuid'

    def post(self, request, *args, **kwargs):
        s_response = launch_new_server(request.data).start()
        return s_response


class CollectorDetailsView(generics.RetrieveUpdateDestroyAPIView):
    """This class handles the GET, PUT, PATCH, and DELETE requests."""

    queryset = Collector.objects.all()
    serializer_class = CollectorSerializer
    lookup_field = 'uuid'

