"""
#!/usr/bin/env python3

MASSMAP
Author: David Roccasalva (n33dle)

to do:
- Add udp service scanning
- Better performance/stablity
- Allow dns names and auto resolve IPs regardless of input
- Further enum based on discovered services
- Code better :(
"""

#libraries:
import subprocess
import argparse
from termcolor import colored
import re
import socket

#arguments
parser = argparse.ArgumentParser(description="Massmap: Port scan single or list of IP addresses with masscan then run an agressive nmap scan on the open ports only. This tool will provide the outputs of masscan, nmap and a file containing the nmap commands for each IP address for adhoc scanning. Intensity levels change masscan/nmap rates.",
    add_help=True,
    epilog="EXAMPLE: # python3 massmap.py -f target-ips.txt --intensity obliterate")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--target", "-t", help="Target an individual IP address", dest="target")
#group.add_argument("--file", "-f", type=argparse.FileType('r'), help="Load target IP addresses from a file")
group.add_argument("--file", "-f", dest="file", help="Load target IP addresses from a file")
parser.add_argument("--intensity", "-i", help="Set the intensity of the scan. Options are: 'obliterate' or 'normal' or 'stealth'. Default: 'normal'", dest="intensity")
parser.add_argument("--output", "-o", help="Destination directory, default is current dir. Example: /dest/dir/", dest="output", default="")
parser.add_argument("--version", action="version", version="0.1")
args = parser.parse_args()

#Intensity (change rates here):
masscanRate = ""
nmapRate = ""
if args.intensity == None:
    #normal
    masscanRate = "100"
    nmapRate = "T3"

elif args.intensity == "obliterate":
    masscanRate = "10000"
    nmapRate = "T5"

elif args.intensity == "stealth":
    masscanRate = "10"
    nmapRate = "T1"

else:
    masscanRate = "100"
    nmapRate = "T3"

print (colored("[!] Starting massmap scanner...\n", "blue"))
print (colored("[>] Masscan rate: "+masscanRate, "cyan"))
print (colored("[>] Nmap rate: "+nmapRate, "cyan"))
print (colored("[>] Output directory: "+args.output, "cyan"))


#scan single target:
if args.file is None:
    #masscan
    print (colored("[>] Target: "+args.target+"\n", "cyan"))
    print (colored("[-] Performing a full 65k TCP port scan of "+args.target+" with masscan:", "yellow"))
    subprocess.run(["masscan","--rate="+masscanRate,"-p","0-65535",args.target,"-oL",args.output+args.target+"-full65k.raw-masscan"])
    print (colored("[+] Done - saved as: "+args.output+args.target+"-full65k.raw-masscan", "green"))
    print (colored("[-] Cleaning output for nmap", "yellow"))
    masscanCleaned = open(args.output+args.target+"-cleaned.masscan", "w")
    subprocess.run(["grep","-e","open",args.output+args.target+"-full65k.raw-masscan"], stdout=masscanCleaned)
    print (colored("[+] Done - saved as: "+args.output+args.target+"-cleaned.masscan", "green"))

    #cleanup masscan output to just get IP address and open ports:
    regex = re.compile(r"open tcp (\d+) (\d+\.\d+\.\d+\.\d+)", re.I)

    ip_list = {}

    with open(args.output+args.target+"-cleaned.masscan") as f:
    	lines = f.readlines()
    	for line in lines:
    		port = regex.match(line).group(1)
    		ip = regex.match(line).group(2)
    		# adding each IP address to the array
    		try:
    			ip_list[ip]

    		except KeyError:
    			ip_list[ip] = []
    		#append the open ports for each IP address
    		ip_list[ip].append(port)

    with open(args.output+args.target+"-nmap-command.txt", "a") as f:
        sorted_ips = sorted(ip_list.items(), key=lambda item: socket.inet_aton(item[0]))
        for ip,port in sorted_ips:
            ports = ""
            try:
                for port in port:
                    ports += port + ","
            except KeyError:
                    pass
            line = "nmap -n -v -p " + ports + " -A " + ip + " -oA " + ip
            f.write(line + "\n")
            subprocess.run(["nmap","-n","-v","-"+nmapRate,"-p",ports,"-A",ip,"-oA",args.output+args.target+"-results","-Pn"])
            print (colored("[+] Done - Nmap Results saved as: "+args.output+args.target+"-results.nmap|gnmap|xml", "green"))
    #end

###### targets from file #####

else:
    numofTargets = sum(1 for line in open(args.file))
    print (colored("[>] Scanning "+str(numofTargets)+" targets from file: "+args.file+"\n", "cyan"))

    print (colored("[-] Performing a full 65k TCP port scan of all targets in "+args.file+" with masscan:", "yellow"))
    subprocess.run(["masscan","--rate="+masscanRate,"-p","0-65535","-iL",args.file,"-oL",args.output+args.file+"-full65k.raw-masscan"])
    print (colored("[+] Done - saved as: "+args.output+args.file+"-full65k.raw-masscan", "green"))
    print (colored("[-] Cleaning output for nmap", "yellow"))
    masscanCleaned = open(args.output+args.file+"-cleaned.masscan", "w")
    subprocess.run(["grep","-e","open",args.output+args.file+"-full65k.raw-masscan"], stdout=masscanCleaned)
    print (colored("[+] Done - saved as: "+args.output+args.file+"-cleaned.masscan", "green"))
    print (colored("[-] Starting an nmap scan of all open ports across all targets:", "yellow"))

    #cleanup masscan output to just get IP address and open ports:
    regex = re.compile(r"open tcp (\d+) (\d+\.\d+\.\d+\.\d+)", re.I)

    ip_list = {}

    with open(args.output+args.file+"-cleaned.masscan") as f:
    	lines = f.readlines()
    	for line in lines:
    		port = regex.match(line).group(1)
    		ip = regex.match(line).group(2)
    		# adding each IP address to the array
    		try:
    			ip_list[ip]

    		except KeyError:
    			ip_list[ip] = []
    		#append the open ports for each IP address
    		ip_list[ip].append(port)

    with open(args.output+args.file+"-nmap-commands.txt", "a") as f:
        sorted_ips = sorted(ip_list.items(), key=lambda item: socket.inet_aton(item[0]))
        for ip,port in sorted_ips:
            ports = ""
            try:
                for port in port:
                    ports += port + ","
            except KeyError:
                    pass
            line = "nmap -n -v -p " + ports + " -A " + ip + " -oA " + ip
            f.write(line + "\n")
            print (colored("[>] nmap scanning: "+ip, "red"))
            subprocess.run(["nmap","-n","-v","-"+nmapRate,"-p",ports,"-A",ip,"-oA",args.output+ip+"-results","-Pn"])
            print (colored("[+] Done - Nmap Results saved as: "+args.output+ip+"-results.nmap|gnmap|xml", "green"))

print (colored("[!] massmap scanner complete!", "blue"))
#end
