# Sigma Translator for Securonix

In this Project, Sigma rules are translated into Securonix SIEM query format, that is, Spotter Query Format. Sigma tools are used as framework to build the backend python file and configuration file for Securonix. More details on Sigma can be found [here](https://github.com/SigmaHQ/sigma).

<br/>

This folder contains following files:
1. Securonix Backend file - securonix.py
2. YAML configuration files

<br/>

## Securonix YAML Configuration Files
Multiple YAML configuration files are created based on the functionalities defined in Spotter. Each functionalities represent a YAML configuration file which consists of Sigma attributes mapped to Spotter Attributes.

<br/>

## SIGMA Translator set-up

<br/>

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
<br/>

Translate the Sigma rule into Securonix Spotter Query as:
```
tools/sigma/sigmac.py -t securonix -c tools/config/<yaml-configuration-file> <sigma-rule-file>
```

<br/>

## YAML Configuration files

![image](https://user-images.githubusercontent.com/62869530/113169918-0e309c00-9214-11eb-832f-9cb9d7c1f5dc.png)

<br/>

## Sigma rule translation

The YAML configuration files are created based on the functionality in Spotter, that is, each functioanlity represents a YAML configuration files. Based on the configuration file provided in the input command, spotter query displays the attribute "rg_functionality". The attributes provided in the Sigma rules under "detection" are mapped to the spotter attributes based on the configuration file (fieldmappings). If the attribute mappting is not present in the configuration file, it will be shown as rawevent with index = archive.

<br/>

## Examples

CVE-2021-26858 Exchange Exploitation (experimental)
<br/>

![image](https://user-images.githubusercontent.com/62869530/113162053-edb11380-920c-11eb-8f87-513ea35ab948.png)
<br/>

Spotter Query for CVE-2021-26858 Exchange Exploitation mapped to functionality "Microsoft Windows" (All attributes of Sigma rule mapped to Spotter)
```
tools/sigma/sigmac.py -t securonix -c tools/config/securonix-windows.yml rules/windows/file_event/sysmon_cve_2021_26858_msexchange.yml
```
![image](https://user-images.githubusercontent.com/62869530/113162879-a70fe900-920d-11eb-9ad6-46744631d79d.png)

<br/>

Linux Crond Process (experimental)
<br/>

![image](https://user-images.githubusercontent.com/62869530/113163833-88f6b880-920e-11eb-991f-943ce68db1b5.png)
<br/>

Spotter Query for Linux Crond Process mapped to functionality "Unix / Linux / AIX" (Attributes with no mapping available shown as rawevent with index = archive)
```
tools/sigma/sigmac.py -t securonix -c tools/config/securonix-windows.yml rules/linux/auditd/lnx_auditd_masquerading_crond.yml
```
![image](https://user-images.githubusercontent.com/62869530/113164453-1d611b00-920f-11eb-8270-a475ffafa9ac.png)





