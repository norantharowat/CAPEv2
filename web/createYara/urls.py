# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.urls import re_path
from createYara import views

urlpatterns = [
    re_path(r"^$", views.index, name="createYara"),
    re_path(r"editYara/(?P<family_name>\w+)/$", views.edit_yara, name="editYara"),
    re_path(r"viewYara/", views.viewYara, name="viewYara"),
    
]
