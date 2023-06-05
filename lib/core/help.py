from lib.core.print import *

HELP = "Execute this script as root, and make sure all tools are installed by running install.py!\n" + "To exit the script press 'e' or 'c'.\n" + """
Usage: shreksplosion.py [options]\n
        -u [target]     
        --target [target]  Target url/host (e.g: http://www.site.com) [!REQUIRED!]
        -r --recon         Enable recon scanning (enabled by default)
        -v --vuln          Enable vulnerability scanning (enabled by default)
        -c --cms           Enable CMS scanning (enabled by default)
        -b --brute         Enable brute forcing (disabled by default)
        -qB --quickBrute   Enable quick brute forcing (disabled by default)
        -s --stealth       Enable stealth scanning mode (where possible)
        -l --loud          Enable loud (noisy) scanning mode
        -p [port] 
        --port [port]      Custom port
        -h --help          Show this help menu
        -sK --skip         Skip initial server status check
        -m --multi         Perform a scan on multiple targets, specify them in the \"hosts.txt\" file
        -nN --noNikto      Skip nikto scan(can take very long to finish)
        -cM --cmsMap       Enable CMSMap scan"""
