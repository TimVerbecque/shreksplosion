import json
import subprocess
import time
import validators
import keyboard
import threading
import _thread
import os

from datetime import datetime
from time import strftime 
from inputimeout import inputimeout

from lib.core.banner import *
from lib.core.config import *
from lib.core.help import *
from lib.core.print import *
from lib.core.variables import *

def parameters(multi):
    #Brute force attacks or not
    if "-b" in args or "--brute" in args:
        brute = True
    else:
        brute = False

    #Quick brute force attacks or not
    if "-qB" in args or "--quickBrute" in args:
        quickBrute = True
    else:
        quickBrute = False

    if "-nN" in args or "--noNikto" in args:
        noNikto = True
    else:
        noNikto = False

    if "-cM" in args or "--cmsMap" in args:
        cmsMap = True
    else:
        cmsMap = False

    if "-r" in args or "--recon" in args:
        recon = True
    else:
        recon = False
    
    if "-v" in args or "--vuln" in args:
        vuln = True
    else:
        vuln = False

    if "-c" in args or "--cms" in args:
        cms = True
    else:
        cms = False

    #Scanning mode option
    mode = get_scanning_mode()
    
    #Custom port option
    customPort = get_port()

    #Get url(s) and target(s) + validate
    if multi:
        urls, targets = get_urls()
        return urls, targets, brute, mode, customPort, quickBrute, noNikto, cmsMap, recon, vuln, cms
    else:
        url, target = get_url()
        return url, target, brute, mode, customPort, quickBrute, noNikto, cmsMap, recon, vuln, cms

def get_urls():
    urls = []
    targets = []

    with open("hosts.txt","r") as hosts:
        for site in hosts:
            site = site.lower().rstrip("/")
            if not validators.url(site):
                    target = site
                    url = "https://" + target
            else:
                url = site
                target = get_target(url)
            if not os.path.exists(f"reports_{target}"):
                subprocess.run(["mkdir", f"reports_{target}"])
            urls.append(url)
            targets.append(target)
    return urls, targets

def get_url():
    if "-u" in args or "--target" in args:
        if "-u" in args:
            try:
                site = args[args.index('-u')+ 1]
            except IndexError:
                print(WARN(RED("Please specify your target!")))
                exit()
        else:
            try:
                site = args[args.index('--target')+ 1]
            except IndexError:
                print(WARN(RED("Please specify your target!")))
                exit()
    else:
        print(WARN(RED("Please specify your target!")))
        exit()
    site = site.lower().rstrip("/")
    if not validators.url(site):
        target = site
        url = "https://" + target
    else:
        url = site
        target = get_target(url)
    if not os.path.exists(f"reports_{target}"):
        subprocess.run(["mkdir", f"reports_{target}"])
    return url, target

def get_scanning_mode():
    if ("-s" in args and "-l" in args) or ("--stealth" in args and "--loud" in args) or ("-s" in args and "--loud" in args) or ("--stealth" in args and "-l" in args):
        print(WARN(RED("Please enter only 1 scanning mode!")))
        exit()
    elif "-s" in args or "--stealth" in args:
        mode = "s"
    elif "-l" in args or "--loud" in args:
        mode = "l"
    else:
        mode = "n"
    return mode

def get_port():
    if "-p" in args:
        try:
            customPort = args[args.index('-p')+ 1]
        except IndexError:
            print(WARN(RED("Please also include a port number!")))
            exit()
    elif "--port" in args:
        try:
            customPort = args[args.index('--port')+ 1]
        except IndexError:
            print(WARN(RED("Please also include a port number!")))
            exit()
    else:
        customPort = "n"
    return customPort

def get_target(url):
    if url.startswith("https://"):
        target = url[8:].rstrip("/").rstrip()
    else:
        target = url[7:].rstrip("/").rstrip()
    return target


def valid_url(url, target, customPort):
    VALID = False
    print(FULLINFO("Checking server status."))

    if customPort == "n":
        if ping(target):
            VALID = True
    
    if curl(url, customPort):
        VALID = True

    if VALID:
        print(FULLSUCCESS("Target is reachable!\n"))
    else:
        print(FULLWARN("Target is unreachable!\n"))
        try:
            CONTINUE = inputimeout(prompt=INPUT("Do you still want to continue the scan? (y/n): "), timeout=10)
            if CONTINUE == "n" or CONTINUE == "no" or CONTINUE == "nope":
                print(FULLWARN("Exiting... try again with a valid url."))
                exit()
            else:
                print(FULLWARN("Continuing... but be warned, there's a chance the tool(s) might not work (properly).\n"))
        except Exception:
            print(FULLWARN("No input received after 10 seconds => continuing, there's a chance the tool(s) might not work (properly).\n"))

def ping(target):
    try:
        print(DOING(f"ping {target} -c 4"))
        subprocess.check_output(["ping", "-c", "4", target], shell=False)
        print(SUCCESS("ping successful!"))
        return True                      
    except subprocess.CalledProcessError:
        print(FAIL("ping failed!"))
        return False

def curl(url, customPort):
    try:
        if customPort == "n":
            print(DOING(f"curl -Is {url}"))
            subprocess.check_output(['curl', '-Is', url], shell=False)
            print(SUCCESS(f'curl successful, {url} is online!'))
            return True
        else:
            print(DOING(f"curl -Is {url}:{customPort}"))
            subprocess.check_output(['curl', '-Is', f'{url}:{customPort}'], shell=False)
            print(SUCCESS(f'curl successful, {url} is online!'))
            return True
    except subprocess.CalledProcessError:
        print(FAIL(f'curl failed, {url} is offline!'))
        return False


def get_time():
    #Get current date and time
    return strftime('%d/%m/%Y at %H:%M:%S')

def get_time_file():
    #Get current date and time but version to use it in filenames
    return strftime('%d-%m-%Y_%H-%M-%S')

def get_time_accurate():
    #Get current date and time but version to use it in filenames
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S:%f")


def background_run(CMD, SHELL):
    return subprocess.Popen(
            CMD,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=SHELL
        )


def recon(url, target, mode, port, customPort):
    print(FULLINFO("Starting reconnaissance"))
    t = get_time_file()

    check_header(url, target, customPort)

    if mode == "s":
        scanMode = "1"
    elif mode == "n":
        scanMode = "3"
    elif mode == "l":
        scanMode = "4"

    if customPort != "n":
        url_whatweb = url + ":" + port
    else:
        url_whatweb = url

    output_whatweb = f"reports_{target}/whatweb_{t}.json"
    cmd_whatweb = ["whatweb", "-a", scanMode, url_whatweb, "-v", f"--log-json={output_whatweb}"]

    output_nmap = f"reports_{target}/nmap_{t}.xml"

    if mode == "s":
        print_nmap = DOING(f"nmap -sS -A -p {port} {target} -oX {output_nmap}")
        cmd_nmap = ["nmap", "-sS", "-A", "-p", port, target, "-oX", output_nmap]
    elif mode == "n" or mode == "l":
        print_nmap = DOING(f"nmap -A -p {port} {target} -oX {output_nmap}")
        cmd_nmap = ["nmap", "-A", "-p", port, target, "-oX", output_nmap]

    print(INFO("WhatWeb basic scan"))
    print(DOING(f"whatweb -a {scanMode} {url_whatweb} -v --log-json={output_whatweb}"))

    whatweb_scan = background_run(cmd_whatweb, False)

    nmap_scan = background_run(cmd_nmap, False)

    while whatweb_scan.poll() is None:
        time.sleep(1)

    output, error = whatweb_scan.communicate()
    #print(output, error)
    print(FULLSUCCESS("Whatweb scan completed\n"))

    print(INFO("Nmap scan on target"))
    print(print_nmap)

    while nmap_scan.poll() is None:
        time.sleep(1)

    searchsploit_nmap = background_run(["searchsploit", "--nmap", output_nmap], False)

    output, error = nmap_scan.communicate()
    print(output, error)
    print(FULLSUCCESS("Nmap scan completed\n"))

    while searchsploit_nmap.poll() is None:
        time.sleep(1)

    print(INFO("Check nmap results in exploitdb (searchsploit)"))
    print(DOING(f"searchsploit --nmap {output_nmap}"))
    output, error = searchsploit_nmap.communicate()
    print(output, error)
    print(FULLSUCCESS("Searchsploit analysis finished\n"))

    print(END("Reconnaissance finished\n"))

def check_header(url, target, customPort):
    print(INFO("Checkin headers"))

    f = f"reports_{target}/headers_{get_time_file()}.json"
    t = get_time_accurate()
    result = open(f, "w")
    
    if customPort != "n":
        print(DOING(f"python ../shcheck/shcheck.py {url} -j -i -x -k -p {customPort}"))
        cmd = ["python", "../shcheck/shcheck.py", url, "-j", "-i", "-x", "-k", "-p", customPort]
    else:
        print(DOING(f"python shcheck.py {url} -j -i -x -k"))
        cmd = ["python", "../shcheck/shcheck.py", url, "-j", "-i", "-x", "-k"]

    subprocess.run(cmd, stdout=result)

    with open(f,'r+') as file:
        try:
            file_data = json.load(file)
            file_data.update({"time":t})
            file.seek(0)
            json.dump(file_data, file, indent = 2)
            print(file_data)
        except json.decoder.JSONDecodeError:
            print(file.readlines())

    print(FULLSUCCESS("Header check completed\n"))


def vulners(target, mode, customPort, noNikto):
    print(FULLINFO("Start vulnerability scanning"))
    t = get_time_file()

    if customPort == "n":
        port = ""
    else:
        port = ":" + customPort

    print(INFO("Wafw00f scan "))
    print(DOING(f"wafw00f {target} -o reports_{target}/wafw00f_{t}.json"))

    if not noNikto:
        if customPort == "n":
            nikto = background_run(["nikto", "-h", target, "-followredirects", "-nossl", "-Tuning", "x1", "-C", "all", "-timeout", "8", "-o", f"reports_{target}/nikto_{t}.json"], False)
        else:
            nikto = background_run(["nikto", "-h", target, "-followredirects", "-port", customPort, "-nossl", "-Tuning", "x1", "-C", "all", "-timeout", "8", "-o", f"reports_{target}/nikto_{t}.json"], False)
        
    nuclei2 = background_run(["nuclei", "-u", f"{target}", "-t", "cves/", "-t", "vulnerabilities/", "-t", "technologies/", "-o", f"reports_{target}/nuclei2_{t}.json"], False)

    if mode == "s":
        ssl_tls = background_run([f"testssl", "--sneaky", "-oa", f"reports_{target}/testssl_{t}", f"{target}{port}"], False)
    else:
        ssl_tls = background_run([f"testssl", "-oa", f"reports_{target}/testssl_{t}", f"{target}{port}"], False)
    

    nuclei1 = background_run(["nuclei", "-u", f"{target}", "-as", "-o", f"reports_{target}/nuclei1_{t}.json"], False)

    wafw00f = background_run(["wafw00f", f"{target}", "-o", f"reports_{target}/wafw00f_{t}.json"], False)

    while wafw00f.poll() is None:
        time.sleep(1)
    output, error = wafw00f.communicate()
    print(output, error)
    print(FULLSUCCESS("Wafw00f scan completed\n"))

    with open(f"reports_{target}/wafw00f_{t}.json",'r+') as file:
        try:
            file_data = json.load(file)
            file.seek(0)
            file_data.append({"time":t})
            json.dump(file_data, file, indent = 2)
            file.truncate()
        except json.decoder.JSONDecodeError:
            print(file.readlines())

    print(INFO("Nuclei scan with Wappalyzer"))
    print(DOING(f"nuclei -u {target} -as -o reports_{target}/nuclei1_{t}.json"))
    while nuclei1.poll() is None:
        time.sleep(1)
    output, error = nuclei1.communicate()
    print(output, error)
    print(FULLSUCCESS("Nuclei scan with Wappalyzer completed\n"))

    print(INFO("SSL/TLS scan"))
    if mode == "s":
        print(DOING(f"testssl --sneaky -oa reports_{target}/testssl_{t} {target}{port}"))
    else:
        print(DOING(f"testssl -oa reports_{target}/testssl_{t} {target}{port}"))
    while ssl_tls.poll() is None:
        time.sleep(1)
    output, error = ssl_tls.communicate()
    print(output, error)
    with open(f"reports_{target}/testssl_{t}.json",'r+') as file:
        try:
            file_data = json.load(file)
            file.seek(0)
            file_data.append({"time":t})
            json.dump(file_data, file, indent = 2)
            file.truncate()
        except json.decoder.JSONDecodeError:
            print(file.readlines())

    print(FULLSUCCESS("SSL/TLS scan completed\n"))

    print(INFO("Nuclei scan CVE template"))
    print(DOING(f"nuclei -u {target} -t cves/ -t vulnerabilities/ -t technologies/ -o reports_{target}/nuclei2_{t}.json"))
    while nuclei2.poll() is None:
        time.sleep(1)
    output, error = nuclei2.communicate()
    print(output, error)
    print(FULLSUCCESS("Nuclei scan CVE template completed\n"))

    if not noNikto:
        print(INFO("Nikto basic scan"))
        if customPort == "n":
            print(DOING(f"nikto -h {target} -followredirects -Tuning x1 -C all -nossl -timeout 8 -o reports_{target}/nikto_{t}.json"))
        else:
            print(DOING(f"nikto -h {target} -followredirects -port {customPort} -Tuning x1 -C all -nossl -timeout 8 -o reports_{target}/nikto_{t}.json"))
        while nikto.poll() is None:
            time.sleep(1)
        output, error = nikto.communicate()
        print(output, error)
        with open(f"reports_{target}/nikto_{t}.json",'r+') as file:
            try:
                file_data = json.load(file)
                file_data.update({"time":t})
                file.seek(0)
                json.dump(file_data, file, indent = 2)
            except json.decoder.JSONDecodeError:
                print(file.readlines())

        print(FULLSUCCESS("Nikto scan completed\n"))

    print(END("Vulnerability scanning finished\n"))


def cms(url, target, cmsMap):
    print(FULLINFO("Start CMS scanning/exploiting"))
    t = get_time_file()

    print(INFO("CMSeeK started"))
    print(DOING(f"cmseek -u {url} --follow-redirect"))
    cmseek = background_run(["cmseek", "-u", f"{url}", "--follow-redirect"], False)
    if cmsMap:
        cmsmap = background_run(["python", "../CMSmap/cmsmap.py", url, "-F", "-t", "10", "-o", f"reports_{target}/cmsmap_{t}.txt"], False)

    while cmseek.poll() is None:
        time.sleep(1)
    output, error = cmseek.communicate()
    print(output, error)
    subprocess.run(["mv", f"/usr/share/cmseek/Result/{target}/cms.json", f"reports_{target}/cmseek_{t}.json"], shell=False)
    print(FULLSUCCESS("CMSeeK scan completed\n"))

    #Get the CMS from results
    with open(f"reports_{target}/cmseek_{t}.json", "r") as f:
        type = json.load(f)["cms_name"].lower()
    
    if type == "wordpress":
        if wpscanAPI == "":
            cmd_wpscan = ["wpscan", "--url", f"{url}", "-f", "json", "-o", f"reports_{target}/wpscan_{t}.json"]
        else:
            cmd_wpscan = ["wpscan", "--url", f"{url}", "-f", "json", "--api-token", f"{wpscanAPI}", "-o", f"reports_{target}/wpscan_{t}.json"]
        wpscan = background_run(cmd_wpscan, False)

    elif type == "joomla":
        joomscan = background_run(["joomscan", "-u", url, "-ec"], False)

    if cmsMap:
        print(INFO("CMSmap started"))
        print(DOING(f"python ../CMSmap/cmsmap.py {url} -F -t 10 -o reports_{target}/cmsmap_{t}.txt"))
        while cmsmap.poll() is None:
            time.sleep(1)
        output, error = cmsmap.communicate()
        print(output, error)
        print(FULLSUCCESS("CMSmap scan completed\n"))

    if type == "wordpress":
        print(INFO("WPScan started"))
        if wpscanAPI == "":
            print(DOING(f"wpscan --url {url} -f json -o reports_{target}/wpscan_{t}.json"))
        else:
            print(DOING(f"wpscan --url {url} -f json --api-key {wpscanAPI} -o reports_{target}/wpscan_{t}.json"))
        while wpscan.poll() is None:
            time.sleep(1)
        output, error = wpscan.communicate()
        print(output, error)
        print(FULLSUCCESS("WPScan scan completed\n"))

    elif type == "joomla":
        print(INFO("JoomScan started"))
        print(DOING(f"joomscan -u {url} --ec"))
        while joomscan.poll() is None:
            time.sleep(1)
        output, error = joomscan.communicate()
        #print(output, error)
        os.system(f"mv /usr/share/joomscan/reports/{target}/* reports_{target}/")
        print(FULLSUCCESS("JoomScan completed\n"))

    elif type == "drupal":
        f = f"reports_{target}/droopescan_{t}.json"
        result = open(f, "w")
        cmd = ["droopescan", "scan", "drupal", "-u", url, "--hide-progressbar", "-o", "json"]
        print(INFO("DroopeScan started"))
        print(DOING(f"droopescan scan drupal -u {url} --hide-progressbar -o json"))
        subprocess.run(cmd, stdout=result)
        print(FULLSUCCESS("DroopeScan completed\n"))

    print(END("CMS scanning/exploiting finished\n"))


def bruting(url, target, quickBrute):
    t = get_time_file()
    if quickBrute:
        print(FULLINFO("Start quick brute forcing"))
        print(INFO("Gobuster quick directory scan"))
        print(DOING(f"gobuster dir -w {smallDir} -u {url} -o  -r -n --hide-length"))
        gobuster_quick = background_run(["gobuster", "dir", "-w", smallDir, "-u", url, "-o", f"reports_{target}/gobuster_small_{t}.txt", "-r", "-n", "--hide-length"], False)
        while gobuster_quick.poll() is None:
            time.sleep(1)
        output, error = gobuster_quick.communicate()
        print(output, error)
        print(FULLSUCCESS("Gobuster quick directory scan completed\n"))

    else:
        print(FULLINFO("Start brute forcing"))
        cgi_brute = background_run(["gobuster", "dir", "-w", cgi, "-u", url, "-o", f"reports_{target}/gobuster_cgi_{t}.txt", "-r"], False)
        subdomain_long = background_run(["amass", "enum", "-src", "-ip", "-brute", "-json", f"reports_{target}/amass_{t}.json", "-min-for-recursive", "2", "-d", target], False)

        print(INFO("Gobuster CGI directory scan"))
        print(DOING(f"gobuster dir -w {cgi} -u {url} -o reports_{target}/gobuster_cgi_{t}.txt -r"))
        while cgi_brute.poll() is None:
            time.sleep(1)
        output, error = cgi_brute.communicate()
        #print(output, error)
        print(FULLSUCCESS("Gobuster CGI directory scan completed\n"))   

        gobuster_long = background_run(["gobuster", "dir", "-w", bigDir, "-u", url, "-o", f"reports_{target}/gobuster_big_{t}.txt", "-r", "-n", "--hide-length"], False)

        print(INFO("Amass subdomain scan"))
        print(DOING(f"amass enum -src -ip -brute -json reports_{target}/amass_{t}.json -min-for-recursive 2 -d {target}"))
        while subdomain_long.poll() is None:
            time.sleep(1)
        output, error = subdomain_long.communicate()
        #print(output, error)
        print(FULLSUCCESS("Amass subdomain scan completed\n"))  

        print(INFO("Gobuster full directory scan"))
        print(DOING(f"gobuster dir -w {bigDir} -u {url} -o reports_{target}/gobuster_big_{t}.txt -r -n --hide-length"))
        while gobuster_long.poll() is None:
            time.sleep(1)
        output, error = gobuster_long.communicate()
        #print(output, error)
        print(FULLSUCCESS("Gobuster full directory scan completed\n"))

        #dirsearch_recursive = background_run(["dirsearch", "-w", smallDir, "-f", "-t", "20", "-u", target, "-r", "5", "-o", f"reports_{target}/dirsearch_{t}.xml"], False)
        #print(INFO("Dirsearch recursive directory scan"))
        #print(DOING(f"dirsearch -w {smallDir} -f -t 20 -u {target} -r 5 -o reports_{target}/dirsearch_{t}.xml"))
        #print(FULLSUCCESS("Dirsearch recursive directory scan completed\n"))

    #There's a problem with Virustotal api keys for this part of the script, for now it isn't used
    print(INFO("Sublist3r quick subdomain scan"))
    print(DOING(f"sublist3r -d {target} -t 4 -o reports_{target}/sublist3r_{t}.txt"))
    sublist3r_cmd = background_run(["sublist3r", "-d", target, "-t", "4", "-o", f"reports_{target}/sublist3r_{t}.txt"], False)
    while sublist3r_cmd.poll() is None:
            time.sleep(1)
    output, error = sublist3r_cmd.communicate()
    print(output, error)
    print(FULLSUCCESS("Sublist3r quick subdomain scan completed\n"))

    print(END("Brute forcing finished\n"))

exit_event = threading.Event()

def monitor_keyboard_input():
    while not exit_event.is_set():
        if keyboard.is_pressed('e') or keyboard.is_pressed('c'):
            exit_event.set()
            _thread.interrupt_main()
            break

def scans(url, target, brute, mode, customPort, quickBrute, noNikto, cmsMap, rec, vuln, cmss):
    print("\n" + SUCCESS(f"URL: {url}\n") + SUCCESS(f"Starting: {get_time()}\n") + "")

    if "-sK" not in args and "--skip" not in args and mode != "s":
        valid_url(url, target, customPort)

    if customPort == "n":
        port = "80,443"
    else:
        port = customPort
    
    keyboard_thread = threading.Thread(target=monitor_keyboard_input)
    keyboard_thread.start()

    try:
        if rec or (not rec and not vuln and not cmss):
            recon(url, target, mode, port, customPort)

        if vuln or (not rec and not vuln and not cmss):
            vulners(target, mode, customPort, noNikto)

        if cmss or (not rec and not vuln and not cmss):
            cms(url, target, cmsMap)

        if brute or quickBrute:
            if mode == "s":
                print(WARN("You enabled stealth mode but gave the brute force argument, so all bruteforce attacks will be canceled!\n"))
            else:
                bruting(url, target, quickBrute)

    finally:
        exit_event.set()
        keyboard_thread.join()

    print(FULLGREENWARN("Script completed!"))
    print(INFO(f"You'll find all the output files in the following directory: reports_{target}"))

    if exit_event.is_set():
        print(FULLWARN("Exiting..."))
        # Perform any cleanup or exit actions here
        return


def main():
    print(BANNER)

    if len(args) <= 1 or "-h" in args or "--help" in args:
        print(HELP)
        exit()
    
    if "-m" in args or "--multi" in args:
        urls, targets, brute, mode, customPort, quickBrute, noNikto, cmsMap, recon, vuln, cms = parameters(True)
        print("\n" + FULLGREENWARN("Starting multi-target pentest"))
        for url in urls:
            target = targets[urls.index(url)]
            scans(url, target, brute, mode, customPort, quickBrute, noNikto, cmsMap, recon, vuln, cms)
    else:
        print("\n" + FULLGREENWARN("Starting single-target pentest"))
        url, target, brute, mode, customPort, quickBrute, noNikto, cmsMap, recon, vuln, cms = parameters(False)
        scans(url, target, brute, mode, customPort, quickBrute, noNikto, cmsMap, recon, vuln, cms)

try:
    main()
except KeyboardInterrupt:
    print("" + FULLWARN("Exiting..."))