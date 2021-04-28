# massmap
Performs a port scan of a single or list of IP addresses with masscan then runs an agressive nmap scan on the open ports only. This tool will provide the outputs of masscan, nmap and a file containing the nmap commands for each IP address for adhoc scanning. Intensity levels change masscan/nmap rates
Why? I typically like to scan targets with masscan first, then go deeper with nmap. I've just automated this a bit better then doing it manually.

# Installation:
`pip3 install -r requirements.txt`

# Features:
Nothing special about this tool... It simply scans IP addresses with masscan then the masscan output is parsed, cleaned and sorted to scan with nmap only targetting the open ports for each IP address and outputs everything to file.

You can change the masscan/nmap rates as an argument with the `--intensity` flag. The options are:

* normal (default when you don't add this flag): masscan: `--rate=100` & nmap: `-T3`
* stealth: masscan: `--rate=10` nmap: `-T1`
* obliterate: masscan: `--rate=10000` nmap: `-T5`

There are quite a few outputs to file. In summary:
* `<ip>-results.nmap|gnmap|xml` = the results of the nmap scan for each IP address
* `<ip/filename>-cleaned.masscan` = this is simply just the "cleaned" masscan output for nmap and not that valuable
* `<ip/filename>-full65k.raw-masscan` = this is your typical masscan "-oL" output
* `<ip/filename>-nmap-command(s).txt` = this is a list of nmap commands per IP address with the correct open ports for each IP. Useful for adhoc scans later if needed.

# How to use:
You can scan either a single IP address or a list of IPs from a file.

Use `-t` or `--target` for a single target

example:
`python3 massmap.py -t 192.168.1.20`

Use `-f` or `--file` to scan a list of IP addresses in a file

example:
`python3 massmap.py -f targets.txt`

# Example:
The following will perform a masscan/nmap scan against a list of IPs in targets.txt with the highest masscan/nmap rates and output everything to the ~/scans/projectx directory.

`python3 massmap.py -f targets.txt --intensity obliterate -o ~/scans/projectx`
