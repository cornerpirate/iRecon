#!/usr/bin/python
# calling: ./iRecon.py <hostname>
# for example: ./iRecon.py www.pentest.co.uk
# 
# Copyright 2015 cornerpirate.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
 
import sys
import socket
import os
from tld import get_tld
from tld.utils import update_tld_names
import commands

# Sanity check the calling parameters
if len(sys.argv)!=2:
	print "Usage:  \t" + sys.argv[0] + " <hostname>"
	print "Example:\t" + sys.argv[0] + " www.pentest.co.uk" 
	sys.exit(-1)

# We get here there is the correct number of parameters

# sync top level domains with mozilla if the user is root
if os.geteuid() == 0:
	update_tld_names()
else:
	print "Not running as root, you are going to need those privs to nmap properly"
	sys.exit(-1)

# hostname is the real name for our argument
hostname = sys.argv[1]
ip = ""
domain  = ""

# try to resolve ip
try:
	ip = socket.gethostbyname(hostname)
except:
	print "== Error on resolving IP check that hostname resolves: "
	print sys.exc_info()
	sys.exit(-1)

# get domain name
domainname = get_tld("http://"+hostname)

print "== We have everything we need to do reconnaissance"
print "\tHostname: " + hostname
print "\tDomain: " + domainname
print "\tIP: " + ip
print "== Doing the information gathering"


whoisipcmd='whois ' + ip + ' > whois-ip-' + ip + '.txt'
print "Whois IP lookup cmd: " + whoisipcmd
print commands.getoutput(whoisipcmd)
whoisdomaincmd='whois ' + domainname + ' > whois-domain-' + domainname + '.txt'
print "Whois DOMAIN lookup cmd: " + whoisdomaincmd
print commands.getoutput(whoisdomaincmd)
nmappingcmd= 'nmap -sn -PE ' + ip + ' -oA nmap-ping-sweep-' + ip 
print "Nmap Ping cmd: " + nmappingcmd
print commands.getoutput(nmappingcmd) 
nmaptop20portscmd= 'nmap -sS -sU -P0 --reason --top-ports 20 ' + ip + ' -oA nmap-top-20-ports-' + ip 
print "Nmap top 20 ports cmd: " + nmaptop20portscmd
print commands.getoutput(nmaptop20portscmd) 
# check nmap ouput for open ports to then run traceroute

opentcpportcmd='cat nmap-top-20-ports-' + ip + '.nmap | grep "tcp" | grep "open\s" --color -m 1 | cut -d "/" -f 1'
print "Finding open tcp port cmd: " + opentcpportcmd
opentcpport = commands.getoutput(opentcpportcmd)
if len(opentcpport) != 0:
	print "Found open port: " + opentcpport
	nmaptraceroutecmd='nmap -p ' + opentcpport + ' -tr ' + ip + ' -oA nmap-traceroute-' + ip + '-' + opentcpport 
	print "Nmap tcp traceroute command: " + nmaptraceroutecmd
	print commands.getoutput(nmaptraceroutecmd)	
else:
	print "No open tcp port found"

# now do full SYN and top 500 UDP
nmapfullsyncmd= 'nmap -sS -P0 --reason -p 1-65535 -sV -A ' + ip + ' -oA nmap-full-syn-' + ip
print "Nmap full SYN cmd: " + nmapfullsyncmd
print commands.getoutput(nmapfullsyncmd)

nmaptop500udp= 'nmap -sU -P0 --reason --top-ports 500 ' + ip + ' -oA nmap-udp-top-500-' + ip
print "Nmap top 500 UDP cmd: " + nmaptop500udp
print commands.getoutput(nmaptop500udp)





