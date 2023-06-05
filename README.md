# Shreksplosion
## Description
Shreksplosion is a Linux tool written in Python that automates (part of) a web application pentest. The pentest is automated by chaining a variety of different tools, these tools inclulde:
- Amass
- CMSeeK
- CMSmap
- Droopescan
- Gobuster
- JoomScan
- Nikto
- Nmap
- Nuclei
- Searchsploit
- Shcheck
- Sublist3r
- TestSSL
- Wafw00f
- WhatWeb
- WPScan

The goal is to save as much time as possible during web application pentests by automating as many security tests as possible, by quickly identifying low-hanging fruit vulnerabilities, and then spend more time on more manually testing interesting and tricky stuff!

### Features:
- Reconnaissance
- CVE lookup
- Vulnerability scanning
- CMS scanning
- Brute force attack

## Installation
Clone the repo (may require a password):
```
git clone https://Refracted-Security@dev.azure.com/Refracted-Security/Refracted%20-%20web%20api%20automation%20%28Shreksplosion%29/_git/Refracted%20-%20web%20api%20automation%20%28Shreksplosion%29 Shreksplosion
```
Make the ```install.sh``` file executable and change directory:
```
cd Shreksplosion; sudo chmod +x install.sh
```
Run the installation script:
```
sudo ./install.sh
```
Activate the virtual environment:
```
source venv/bin/activate
```

## Usage
To run Shreksplosion:
```
sudo python shreksplosion.py -u example.com
```

### Arguments:
```
-u [target]     
--target [target]  Target url/host (e.g: https://example.com or example.com) [!REQUIRED!]
-r --recon         Enable recon scanning (enabled by default, if entered only specified modes will be run)
-v --vuln          Enable vulnerability scanning (enabled by default, if entered only specified modes will be run)
-c --cms           Enable CMS scanning (enabled by default, if entered only specified modes will be run)
-b --brute         Enable brute forcing (disabled by default)
-qB --quickBrute   Enable quick brute forcing (disabled by default)
-s --stealth       Enable stealth scanning mode (where possible)
-l --loud          Enable loud (noisy) scanning mode
-p [port]
--port [port]      Give a custom port where the tests should be performed on
-h --help          Show the help menu
-sK --skip         Skip initial server status check
-m --multi         Perform a scan on multiple targets, specify them in the "hosts.txt" file
-nN --noNikto      Skip nikto scan (can take very long to finish)
-cM --cmsMap       Enable CMSMap scan (disabled by default, can take very long to finish)
```

## Config-files
The config.py file allows you to give custom wordlists for the brute force attacks and add an API key for WPScan. The hosts.txt file allows you to list all hosts you want to scan, to use this file when scanning use the -m or --multi option.
#### Default ```config.py``` file
```
smallDir = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"
bigDir = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"
cgi = "/usr/share/seclists/Discovery/Web-Content/CGIs.txt"
wpscanAPI = ""
```
```smallDir``` and ```bigDir``` are just a small and big wordlist for general directory brute forcing and then you have ```cgi``` which is for CGI directory brute forcing.\
Between the quotes after ```wpscanAPI``` you can enter an API key for the WPScan tool, if you don't have one you can get one for free here https://wpscan.com/api.

#### Default ```hosts.txt``` file
```
https://example.com
https://domain.com
```
Edit the file to so it is configured to your needs, place one host per line (both urls and domain names are allowed).

##  Credits
Resources I used during the development of this script:
- Hacktricks (https://book.hacktricks.xyz)
- Jok3r (https://github.com/koutto/jok3r)
- Sn1per (https://github.com/1N3/Sn1per)