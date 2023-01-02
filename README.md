## CAPE: Malware Configuration And Payload Extraction - [Documentation](https://capev2.readthedocs.io/en/latest/#)

This repository is a fork from the [CAPEv2](https://github.com/kevoreilly/CAPEv2) repository developed by kevoreilly. Our contribution focuses on malware family detection using Yara rules. CAPEv2 already supports yara rules for almost 480 malware families, you can find them in data/yara/CAPE folder after CAPEv2 installation. Our contribution is divided into two parts:

- Creating an automated pipeline that allows users to submit malware samples from the CAPE GUI, and create Yara rules using an automatic yara generation tool, we use [YarGen](https://github.com/Neo23x0/yarGen) to achieve this task.

- Integrate an open-source repository of up-to-date Yara rules, we incorporated the [reversing labs](https://github.com/reversinglabs/reversinglabs-yara-rules) yara rules repository and set a listener to fetch new updates in the repository automatically.   

## Requirements

-	First you need to install the yarGen tool for automatic yara rules generation, please install yarGen in the opt folder in Linux and give the yarGen folder a user and group of cape:

    ```
    sudo chown -R cape:cape yarGen-0.23.4
    ```
    
- Clone the reversing labs yara rules repository in the opt folder and give it a user and group of cape:

    ```
    sudo chown -R cape:cape reversinglabs-yara-rules
    ```
 Your opt folder should look like this:
 
![5TkxI0Ek](https://user-images.githubusercontent.com/43759597/210270170-0c8dd37f-63ef-46ae-b7af-a7aa72518f78.png)

## How to make it work

After installing CAPEv2 as mentioned in the main repository, you will have a user and a group created named cape, you will also have a virtual environment created with poetry.

- Whenever there is a missing python module, download it using pip from the virtual environment, we will need to install a library called GitPython to track updates in the reversing labs repository, do it this way:

    ```
    /home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.10/bin/pip install GitPython
    ```
    
- While installing yarGen download its requirements this way:

    ```
    /home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.10/bin/pip install -r requirements.txt
    ```
    
- After installing cape you should have a storage folder in /CAPEv2/storage, make sure you have the create_yara and temp folders, they will be used to create the automatic yara rules. 

![gCyFdDQs](https://user-images.githubusercontent.com/43759597/210270610-ea305bc9-1256-4969-834c-5ed49b7f2379.png)

-	When adding new yara rules in the CAPEv2/data/yara/CAPE folder we need to restart the cape-processor service to make CAPE use the new yara rules:

    ```
    Sudo systemctl restart cape-processor.service 
    ```
    
    - To restart the service from the code we need to allow the cape user to restart it without password to do so we open the sudoers file 
        ```
        sudo visudo
        ```
    - And add the following line
    
        ![AI5rymU0](https://user-images.githubusercontent.com/43759597/210270765-59564782-6472-4e7c-897e-b97a15a8136a.png)
        
  -	Run the reveringlabs_updat_yara.py file in the data folder to add all yara rules in the reversing labs directory to CAPE

![fTLYCUcw](https://user-images.githubusercontent.com/43759597/210270973-df6263fa-f0be-43b2-9cbb-6d5bc720e72a.png)
  
- To listen for changes in the remote reversing labs repository, we have a python script in the data folder that does this task, to run it we create a service called update_yara and execute that script from the service 

    ```
    sudo nano /lib/systemd/system/update_yara.service
    ```
    
    - then enter the following code in the service:

    ```
    [Unit]
	Description=Custom Python Service
	Wants=cape-rooter.service
	After=cape-rooter.service
	[Service]
	WorkingDirectory=/opt/CAPEv2/data/
	ExecStart=/home/cape/.cache/pypoetry/virtualenvs/capev2-t2x27zRb-py3.10/bin/python update_yara.py
	User=cape
	Group=cape
	[Install]
	WantedBy=multi-user.target
    ```
    
    - Then reload the daemon, enable the service and start it.
    ```
    sudo systemctl daemon-reload ; sudo systemctl enable update_yara.service ; sudo systemctl start update_yara.service
    ```

##### Now you are ready to use our two added features.

## Create Yara rules with yarGen Demo

[![Capture](https://user-images.githubusercontent.com/43759597/210274949-d06604ca-fa81-4b47-9ecf-58a6a8b1026f.PNG)](https://drive.google.com/file/d/1_5Vc4qnGL7EqeDJBtuONJD0xjJmNoZdZ/view?usp=sharing)

## Virtual Appliance

Since it requires a lot of steps to make our new features work, we exported the virtual machine running CAPE as an OVF file, you can download the ready to use machine from here:
    
    
