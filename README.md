# iRecon - another reconnaissaince script
There are many recon scripts out there which are useful and probably better by miles. This is just one I needed to land grab info relevant to me about a target.
This will simply do the following:
* Given a FQDN (a full hostname) like "www.google.co.uk".
* It will resolve the IP if resolvable
* It will extract the domain from the hostname i.e. "google.co.uk"
* It will then make the following queries
	* whois `<ip>`
	* whois `<domainname>`
	* nmap -sn -PE `<ip>` # check if ICMP echo responses are enabled on the target.
	* nmap -sS -sU -P0 --top-ports 20 `<ip>` # check for the 20 most common TCP/UDP ports.
	* nmap -p `<open port>` -tr `<ip>` # issue a TCP traceroute to any one open TCP port discovered by previous command.
	* nmap -sS -P0 --reason -p 1-65535 -sV -A <ip> # do full SYN scan ports 1-65535
	* nmap -sU -P0 --reason --top-ports 500 <ip> # Increase UDP to 500 most common


# Pre-Requisites
* TLD python package: https://pypi.python.org/pypi/tld
* Install using: "pip install tld".
* nmap must be within your path.
* works only on *nix.
