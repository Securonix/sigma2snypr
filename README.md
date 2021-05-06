# Sigma Translator for Securonix Snypr Platform

This repository hosts the backend Sigma convertor and releavent field mapping configuration files requires by the Sigma Framework to convert Sigma rules (YAML format) into Spotter queries
More details on Sigma can be found [here](https://github.com/SigmaHQ/sigma).

## Setup and Usage Guide

Download the sigma code from [here](https://github.com/SigmaHQ/sigma). Install Python Repositories using requirements.txt as
```
pip3 install -r tools/requirements.txt
```

Add the backend file of Securonix, that is, "securonix.py" from the current github repository to the folder:
```
tools/sigma/backends/
```

Add the YAML configuration files from the current github respository to the folder:
```
tools/config/
```

Translate the Sigma rule into Securonix Spotter Query as:
```
tools/sigma/sigmac.py -t securonix -c tools/config/<yaml-configuration-file> <sigma-rule-file>
```
## Configuration file references for Securonix functionalities

Multiple YAML configuration files are created based on the functionalities defined in Spotter. Each functionalities represent a YAML configuration file which consists of Sigma attributes mapped to Spotter Attributes.


| Functionality                         | YAML Configuration File      |
|---------------------------------------|------------------------------|
| Web Server                            | securonix_webserver.yml      |
| Network Access Control / NAC          | securonix_nac.yml            |
| DNS / DHCP                            | securonix_dns_dhcp.yml       |
| Web Proxy                             | securonix_webproxy.yml       |
| Endpoint Management Systems           | securonix_ems.yml            |
| Unix / Linux / AIX                    | securonix_linux.yml          |
| Authentication / SSO / Single Sign-On | securonix_authentication.yml |
| Next Generation Firewall              | securonix_ngfw.yml           |
| Microsoft Windows                     | securonix_windows.yml        |
| Microsoft Windows Powershell          | securonix_win_powershell.yml |
| Cloud Services / Applications         | securonix_cloud.yml          |


## Examples

CVE-2021-26858 Exchange Exploitation (experimental)
![image](https://user-images.githubusercontent.com/62869530/113162053-edb11380-920c-11eb-8f87-513ea35ab948.png)
Spotter Query for CVE-2021-26858 Exchange Exploitation mapped to functionality "Microsoft Windows" (All attributes of Sigma rule mapped to Spotter)
```
tools/sigma/sigmac.py -t securonix -c tools/config/securonix-windows.yml rules/windows/file_event/sysmon_cve_2021_26858_msexchange.yml
```
![image](https://user-images.githubusercontent.com/62869530/113162879-a70fe900-920d-11eb-9ad6-46744631d79d.png)

Linux Crond Process (experimental)
![image](https://user-images.githubusercontent.com/62869530/113163833-88f6b880-920e-11eb-991f-943ce68db1b5.png)
Spotter Query for Linux Crond Process mapped to functionality "Unix / Linux / AIX" (Attributes with no mapping available shown as rawevent with index = archive)
```
tools/sigma/sigmac.py -t securonix -c tools/config/securonix-windows.yml rules/linux/auditd/lnx_auditd_masquerading_crond.yml
```
![image](https://user-images.githubusercontent.com/62869530/113164453-1d611b00-920f-11eb-8270-a475ffafa9ac.png)


## Version 
The current release version is **0.1**

This is a ***BETA*** release


## Limitations / Known Issues

1. Supported Snypr version is 6.4
2. Fallback to rawEvent and index=archive when field mappings are not found
3. Not all Sigma rules are supported. We are working towards adding support for as many rules as possible.
4. Unsupported conditions/modifiers
    - Modifiers
        - re
        - base64
        - base64offset
        - utf16le
        - utf16be
        - utf16
        - wide
    - Conditions
        - Aggregate Functions
            - min
            - max
            - avg
            - sum
        - NEAR
5. (BUG) In some queries the NOT operator is placed incorrectly

