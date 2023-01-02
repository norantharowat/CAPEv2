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

![alt text](https://www.dropbox.com/s/c0xjd49s6j36j3k/2023-01-02%2019_55_06-Window.png?dl=0)
