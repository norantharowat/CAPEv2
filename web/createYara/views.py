# encoding: utf-8
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import random
import sys
import tempfile
from base64 import urlsafe_b64encode

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
import re
import shutil

sys.path.append(settings.CUCKOO_PATH)
from uuid import NAMESPACE_DNS, uuid3

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.utils import generate_fake_name, get_options, get_user_filename, sanitize_filename, store_temp_file
from lib.cuckoo.common.web_utils import (
    _download_file,
    all_nodes_exits_list,
    all_vms_tags,
    download_file,
    download_from_vt,
    get_file_content,
    parse_request_arguments,
    perform_search,
    process_new_dlnexec_task,
    process_new_task_files,
)
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.rooter import _load_socks5_operational, vpns

# this required for hash searches
cfg = Config("cuckoo")
routing = Config("routing")
repconf = Config("reporting")
processing = Config("processing")
aux_conf = Config("auxiliary")
web_conf = Config("web")

VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]

db = Database()

from urllib3 import disable_warnings

disable_warnings()

logger = logging.getLogger(__name__)



# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


def force_int(value):
    try:
        value = int(value)
    except Exception:
        value = 0
    finally:
        return value




def save_sample_files(samples, details, family_name):

    samples_folder_path = os.path.join(settings.CUCKOO_PATH, "storage", "create_yara", family_name)

    if not os.path.exists(samples_folder_path):
        os.makedirs(samples_folder_path)
    for sample in samples:
        filename = sample.name
        # Error if there was only one submitted sample and it's empty.
        # But if there are multiple and one was empty, just ignore it.
        if not sample.size:
            details["errors"].append({sample.name: "You uploaded an empty file."})
            continue

        with open(os.path.join(samples_folder_path, filename), "wb") as file:
            # If filedata is file object, do chunked copy.
            
            file.write(sample.read())

def create_yara(family_name):

    samples_folder_path = os.path.join(settings.CUCKOO_PATH, "storage", "create_yara", family_name)
    yara_folder_path = os.path.join(settings.CUCKOO_PATH, "storage", "temp")

    try:
        
        # out = os.system('python3 /home/noran/Documents/yarGen-0.23.4/yarGen.py --nosuper -m '+ samples_folder_path + ' -o '+ yara_folder_path +'/' + family_name+'.yar ')
        out = os.system('python3 /opt/yarGen-0.23.4/yarGen.py --nosuper -m '+ samples_folder_path + ' -o '+ yara_folder_path +'/' + family_name+'.yar ')
        
        if out == 0:
            yara_folder_path = os.path.join(settings.CUCKOO_PATH, "storage", "temp",   family_name+'.yar')
            with open(yara_folder_path ) as f:
                old_rule = f.read()
            print(old_rule )
            # rule_file = open(yara_folder_path, 'w+') 
            # old_rule = rule_file.read()
            # print("old rule", old_rule)
            new_rule = re.sub(r"(meta:\n)", r"\1 {0}\n".format('\tcape_type = "' + family_name + ' Payload"'), old_rule)

            with open(yara_folder_path , 'w') as f:
                f.write(new_rule)
            # rule_file.write(new_rule)
            return True
	
    except Exception:
        return False

def get_yara_rule(family_name):
    
    yara_folder_path = os.path.join(settings.CUCKOO_PATH, "storage", "temp",   family_name+'.yar')
    with open(yara_folder_path) as file:
            # If filedata is file object, do chunked copy.
            
            rule = file.read()
    return rule
        
	
   

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, resubmit_hash=False):
    remote_console = False
    # check = False
    if request.method == "POST":
        details = {
            "errors": [],
            "content": False,
            "request": request,
            "task_ids": [],
            "url": False,
            "params": {},
            "headers": {},
            "service": "Local",
            "path": "",
            
            
            "user_id": request.user.id or 0,
        }
        samples = request.FILES.getlist("sample")
        family_name = request.POST.get("family_name")
        save_sample_files(samples, details, family_name)
        completed = create_yara(family_name)
        if completed:
            
#             # return render(request, "createYara/complete.html")
            return redirect("editYara", family_name= family_name)
        else:
            return render(request, "error.html", {"error": "The Yara rule creation process Failed."})
        # return redirect("editYara", family_name= family_name)
    else:  

         

        yara_rules = []
        for file_name in os.listdir(os.path.join(settings.CUCKOO_PATH, "data", "yara",  "CAPE")):
            yara_rules.append(file_name.partition(".")[0])

        return render(
            request,
            "createYara/index.html", {"yara_rules": yara_rules}
          
        )



@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def edit_yara(request, family_name):
    rule = get_yara_rule(family_name)
    CAPE_path = os.path.join(settings.CUCKOO_PATH, "data", "yara",  "CAPE")
    if request.method == "POST":

        if "cancel" in request.POST:

            with open(os.path.join(CAPE_path, family_name +'.yar' ), "w") as file:
            # If filedata is file object, do chunked copy.
            
                file.write(rule)

            os.system("sudo systemctl restart cape-processor.service")

            return render(request, "createYara/complete.html")
        else:
            edited_rule = request.POST.get("edited_yara")
            with open(os.path.join(CAPE_path, family_name +'.yar' ), "w") as file:
            # If filedata is file object, do chunked copy.
            
                file.write(edited_rule)

            os.system("sudo systemctl restart cape-processor.service")
            return render(request, "createYara/complete.html")
    else:
        
        return render(request, "createYara/editYara.html", {"family_name" :family_name, 'rule': rule})



@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def viewYara(request):
    

    if request.method == "POST":
        file_name = request.POST.get("file_name")
        try:

            shutil.rmtree(os.path.join(settings.CUCKOO_PATH, "storage", "create_yara", file_name))
            os.remove(os.path.join(settings.CUCKOO_PATH, "storage", "temp", file_name + '.yar'))
            os.remove(os.path.join(settings.CUCKOO_PATH, "data", "yara",  "CAPE", file_name + '.yar'))

            os.system("sudo systemctl restart cape-processor.service")
        except Exception:
            return render(request, "error.html", {"error": "An Error occured while deleting."}) 

    
            
        return redirect("viewYara")
    else:
        yara_files = []
        for file_name in os.listdir(os.path.join(settings.CUCKOO_PATH, "storage", "temp")):
            yara_files.append(file_name.partition(".")[0])

        return render(request, "createYara/viewYara.html" , {"yara_files": yara_files})

