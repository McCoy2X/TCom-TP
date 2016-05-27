#! /usr/bin/env python

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

from subprocess import *

from pyx import *

# ICMP: http://www.ietf.org/rfc/rfc792.txt
# ttl: time to live (hop limit)
# https://en.wikipedia.org/wiki/Time_to_live

def myTraceRoute(url):
	print 'todo'

# http://www.secdev.org/projects/scapy/doc/usage.html
def try_attribute_structure(url):

	# build packets
	pcks = IP(dst=url, ttl=range(15)) / ICMP()
	
	# sr returns a list of two tuples: (<Results: TCP:0 UDP:0 ICMP:0 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:5 Other:0>)
	ans, unans = sr(pcks, timeout=1)

	print 'Answered'
	print ans.show()

	print 'Unanswered'
	print unans.show()


	print '-'*100

	print ans[ICMP].pdfdump('packets.pdf',layer_shift=1) # looks like this prints the whole IP/ICMP package

	print ans[ICMP][0]

	print '\nRequest'
	ls(ans[ICMP][0][1])
	
	# on fail (timeout) you get 4 responses?
	print '\nResponse'
	ls(ans[ICMP][0][0])

	# # now that we have identified the different attributes, let's try to access them
	# print ans[ICMP][0][1].id # id doesnt repeat, but version does. doesn't work with version

	# for response in ans[0][ICMP]: # iterate tuples
	# 	print response.display()

if __name__ == "__main__":
    try_attribute_structure('www.google.com')
    # myTraceRoute('www.google.com')