# /api/urls.py

from django.conf.urls import url, include
from rest_framework.urlpatterns import format_suffix_patterns
from .views import *


urlpatterns = {
    url(r'^collector/$', CollectorCreateView.as_view(), name="create"),
    url(r'^collector/(?P<uuid>[0-9a-z]{1,20})/$', CollectorDetailsView.as_view(), name="details"),
    #url(r'^collector/(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]+)/$', CollectorDetailsView.as_view(), name="details"),
    url(r'^group/$', GroupCreateView.as_view(), name="create"),
    url(r'^group/(?P<uuid>[0-9a-z]{1,20})/$', GroupDetailsView.as_view(), name="details"),
    #url(r'^group/(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]+)/$', GroupDetailsView.as_view(), name="details"),
    #url(r'^totalgroups/$', TotalGroupsCreateView.as_view(), name="create"),
    url(r'^totalgroups/(?P<pk>[1]+)/$', TotalGroupsDetailsView.as_view(), name="details"),
}

urlpatterns = format_suffix_patterns(urlpatterns)