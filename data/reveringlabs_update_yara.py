import os
import shutil
import re
import glob

def search_write_in_file(file_name, string_to_search, description):
    with open(file_name, "r+") as file_obj:
        text = file_obj.read()
    new_text = re.sub(string_to_search, r"\1 {0}\n".format(description), text)
    with open(file_name, "w") as file_obj:
        file_obj.write(new_text)

def preprocess_reversing_labs():

    #source_folder = r"./reversinglabs-yara-rules/yara/"
    #temp_folder = r"./temp"
    source_folder = r"/opt/reversinglabs-yara-rules/yara/"
    temp_folder = r"/opt/CAPEv2/data/temp"
	

    if not os.path.isdir(temp_folder) :
        os.mkdir(temp_folder)
    
    for dir_name in os.listdir(source_folder):
        dir = source_folder + dir_name
        for file_name in os.listdir(dir):
            if dir_name.capitalize() in file_name:
                x = file_name.partition(dir_name.capitalize() + ".")
                source = source_folder + dir_name + "/" + file_name
                f_name = x[2].partition(".")
                temp = temp_folder + "/" + f_name[0] + ".yar"
                shutil.copyfile(source, temp)
    for f in os.listdir(temp_folder):
        source_file = temp_folder + "/" + f
        malfamily= f.split('.')

        search_write_in_file(source_file, r"(meta:\n)", '\tcape_type = "' + malfamily[0] + ' Payload"')
        # search_write_in_file(source_file, r"(meta:\n)", '\tmalfamily = "' + malfamily[0] + '"')

            
def add_revering_labs_to_cape():

    temp_folder = r"/opt/CAPEv2/data/temp/"
    cape_folder = r"/opt/CAPEv2/data/yara/CAPE/"
    # temp_folder = r"./temp/"
    # cape_folder = r"./CAPE/"
    files = []
    temp_files =[]

   

    for item in os.listdir(temp_folder):
        temp_files.append(item)    

    for item in os.listdir(cape_folder):
        if ".yar" in item:
            files.append(item)      


   
    
    for f in os.listdir(temp_folder):

        source = temp_folder  + f
        cape = cape_folder + f

        if f in files:
            
            # with open('/opt/CAPEv2/data/yara/CAPE/'+ f, 'a') as outfile:
            with open(cape_folder + f, 'w') as outfile:
                with open(source) as infile:
                    outfile.write(infile.read())

        else:
            
            shutil.copyfile(source, cape)
            
    os.system('sudo systemctl restart cape-processor.service')

  

def delete_temp():
    temp_folder = r"/opt/CAPEv2/data/temp"
    # temp_folder = r"./temp"
    files = glob.glob(temp_folder+"/*")
    for f in files:
        os.remove(f)


preprocess_reversing_labs()
add_revering_labs_to_cape()
delete_temp()