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
#
# == Developers
# cornerpirate - https://twitter.com/cornerpirate
# xpn - https://twitter.com/_xpn_
# == Changelog
# 04/12/2015 - xpn - resrctured to add in plugin support and accept ip address
# 04/12/2015 - cornerpirate - improved usage instructions
import sys
import socket
import os
from tld import get_tld
from tld.utils import update_tld_names
import commands
import argparse
import re

IP_REGEX = "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

class ReconPlugin(object):
	_requireHostname = False
	_target = ""
	
	def __init__(self, requireHostname=False):
		self._requireHostname = requireHostname
		
	def run(self, target):
		raise NotImplementedError

''' Completes a WHOIS check on the provided IP address '''
class ReconIPWhoIsPlugin(ReconPlugin):
	def __init__(self):
		super(ReconIPWhoIsPlugin, self).__init__()
		
	def run(self, target):
		whoisipcmd='whois ' + target + ' > whois-ip-' + target + '.txt'
		print "Whois IP lookup cmd: " + whoisipcmd
		print commands.getoutput(whoisipcmd)

''' Completes a WHOIS check on the provided domain name '''
class ReconHostnameWhoIsPlugin(ReconPlugin):
	def __init__(self):
		super(ReconHostnameWhoIsPlugin, self).__init__(requireHostname=True)
		
	def run(self, target):
		
		domainname = get_tld("http://"+target)
		
		whoisdomaincmd='whois ' + domainname + ' > whois-domain-' + domainname + '.txt'
		print "Whois DOMAIN lookup cmd: " + whoisdomaincmd
		print commands.getoutput(whoisdomaincmd)
		
''' Runs a number of NMAP scans against the provided target '''
class ReconNmapPlugin(ReconPlugin):
	def __init__(self):
		super(ReconNmapPlugin, self).__init__()
		
	def run(self, target):
		nmappingcmd= 'nmap -sn -PE ' + target + ' -oA nmap-ping-sweep-' + target 
		print "Nmap Ping cmd: " + nmappingcmd
		print commands.getoutput(nmappingcmd) 
		nmaptop20portscmd= 'nmap -sS -sU -P0 --reason --top-ports 20 ' + target + ' -oA nmap-top-20-ports-' + target 
		print "Nmap top 20 ports cmd: " + nmaptop20portscmd
		print commands.getoutput(nmaptop20portscmd) 
		# check nmap ouput for open ports to then run traceroute
		
		opentcpportcmd='cat nmap-top-20-ports-' + target + '.nmap | grep "tcp" | grep "open\s" --color -m 1 | cut -d "/" -f 1'
		print "Finding open tcp port cmd: " + opentcpportcmd
		opentcpport = commands.getoutput(opentcpportcmd)
		if len(opentcpport) != 0:
			print "Found open port: " + opentcpport
			nmaptraceroutecmd='nmap -p ' + opentcpport + ' -tr ' + target + ' -oA nmap-traceroute-' + target + '-' + opentcpport 
			print "Nmap tcp traceroute command: " + nmaptraceroutecmd
			print commands.getoutput(nmaptraceroutecmd)	
		else:
			print "No open tcp port found"
		
		# now do full SYN and top 500 UDP
		nmapfullsyncmd= 'nmap -sS -P0 --reason -p 1-65535 -sV -A ' + target + ' -oA nmap-full-syn-' + target
		print "Nmap full SYN cmd: " + nmapfullsyncmd
		print commands.getoutput(nmapfullsyncmd)
		
		nmaptop500udp= 'nmap -sU -P0 --reason --top-ports 500 ' + target + ' -oA nmap-udp-top-500-' + target
		print "Nmap top 500 UDP cmd: " + nmaptop500udp
		print commands.getoutput(nmaptop500udp)


''' Engine responsible for executing all added plugins against a target '''
class ReconEngine:
	_isHostname = False
	_target = ""
	_ip = ""
	_hostnamePlugins = []
	_plugins = []
	
	def __init__(self, target, isHostname=False):
		self._isHostname = isHostname
		self._target = target
	
	''' Add a plugin to the Recon Engine '''		
	def addPlugin(self, plugin):
		if plugin._requireHostname:
			self._hostnamePlugins.append(plugin)
		else:
			self._plugins.append(plugin)
			
	''' Starts the Recon engine '''
	def run(self):
	
		# sync top level domains with mozilla if the user is root
		if os.geteuid() == 0:
			update_tld_names()
		else:
			print "Not running as root, you are going to need those privs to nmap properly"
			sys.exit(-1)
		
		# try to resolve ip
		if self._isHostname:
			try:
				self._ip = socket.gethostbyname(self._target)
			except:
				print "== Error on resolving IP check that hostname resolves: "
				print sys.exc_info()
				sys.exit(-1)
		else:
			self._ip = self._target
		
		# Iterate through plugins which require a hostname to be passed	
		if self._isHostname:
			for plugin in self._hostnamePlugins:
				plugin.run(self._target)
		
		# Iterate through the remaining plugins with an IP
		for plugin in self._plugins:
			plugin.run(self._ip)


if __name__ == '__main__':
	
	# Parse our passed arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('target', help="either a hosname like 'www.google.com' or an ip address, some checks are disabled if ip address is used")
	args = parser.parse_args()
	
	# Try and verify if we have a domain or IP
	if re.match(IP_REGEX, args.target) != None:
		useHostname = False
	else:
		useHostname = True
	
	# Create our engine
	recon = ReconEngine(args.target, useHostname)
	
	# Add plugins here	
	recon.addPlugin(ReconIPWhoIsPlugin())
	recon.addPlugin(ReconHostnameWhoIsPlugin())
	recon.addPlugin(ReconNmapPlugin())
	
	# And run...
	recon.run()
	
