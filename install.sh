#!/bin/bash
apt-get update -y
apt-get install nmap nikto whatweb wfuzz dirsearch gobuster testssl.sh cmseek sublist3r amass exploitdb pip seclists wpscan joomscan wafw00f nuclei -y

virtualenv -q -p /usr/bin/python3 venv
. ./venv/bin/activate

CURRENTDIR=$(pwd)

if [ ! -d "$CURRENTDIR/../CMSmap" ]; then
    cd .. && git clone https://github.com/Dionach/CMSmap && cd CMSmap && pip3 install . && python cmsmap.py -U PC && cd $CURRENTDIR
fi

if [ ! -d "$CURRENTDIR/../shcheck" ]; then
    cd .. && git clone https://github.com/santoru/shcheck.git && cd $CURRENTDIR
fi

nuclei -ut

pip3 install -r requirements.txt