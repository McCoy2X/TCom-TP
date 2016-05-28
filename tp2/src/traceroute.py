#! /usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
from subprocess import *
from pyx import *

# http://www.secdev.org/projects/scapy/doc/usage.html
def test(url):

	# build packets
	pcks = IP(dst=url, ttl=range(15)) / ICMP()
	
	# sr returns a list of two tuples: (<Results: TCP:0 UDP:0 ICMP:0 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:5 Other:0>)
	ans, unans = sr(pcks, timeout=1)

	print 'Answered'
	print ans.show()

	print 'Unanswered'
	print unans.show()


	print '-'*100

	print ans[ICMP].pdfdump('packets.pdf',layer_shift=1) # looks like this prints the whole IP/ICMP package (only incoming)

	print ans[ICMP][0]

	print '\nRequest'
	ls(ans[ICMP][0][0])
	
	# on fail (timeout) you get two packages:
	# 1. IP headers to send you the package
	# 2. Package sent to the last hop?
	# Problem: Attributes are repeated. Idk how to access which from the response packages.
	print '\nResponse'
	ls(ans[ICMP][0][1])

	# # now that we have identified the different attributes, let's try to access them
	# print ans[ICMP][0][1].id # id doesnt repeat, but version does. doesn't work with version

	# for response in ans[0][ICMP]: # iterate tuples
	# 	print response.display()

	print '-'*100

	print '\nIP headers'
	ls(IP)

	print '\n ICMP headers'
	ls(ICMP)

	print '-'*100

	print '\n Final attributes for the problem set:'

	i = 0

	# the request my computer sends to the url
	req_src  = ans[ICMP][i][0].src
	req_dst  = ans[ICMP][i][0].dst
	req_type = ans[ICMP][i][0].type

	# ans[ICMP][i][1].show()

	# response from a hop, can be successful or unsuccessful
	resp_src  = ans[ICMP][i][1].src
	resp_dst  = ans[ICMP][i][1].dst
	resp_type = ans[ICMP][i][1].type 


	if resp_type != 0:

		# when the hop decrements the ttl and ttl = 0, this is the packet the hop receibed.
		hop_src   = ans[ICMP][i][1][1].src
		hop_dst   = ans[ICMP][i][1][1].dst
		hop_type  = ans[ICMP][i][1][1].type

# ICMP: http://www.ietf.org/rfc/rfc792.txt
# ttl: time to live (hop limit)
# https://en.wikipedia.org/wiki/Time_to_live

def myTraceRoute(url):
	
	try:
		host = socket.gethostbyname(url)
	except:
		print "%s: Name or service not known" % url
		return

	print "traceroute to %s (%s)" % (url, host)

	ttl = 1;
	resp_type = -1
	repeat = 3

	while resp_type != 0:

		d = dict()
		failed = 0

		for _ in range(0,repeat):

			pck = IP(dst=url, ttl=ttl) / ICMP() # 28 bytes

			currentTime = time.time() * 1000

			ans, unans = sr(pck, timeout=1, verbose=0)

			elapsedTime = time.time() * 1000 - currentTime

			if len(ans) > 0: # got answers!

				i = 0

				# the request my computer sends to the url
				req_src  = ans[ICMP][i][0].src
				req_dst  = ans[ICMP][i][0].dst
				req_type = ans[ICMP][i][0].type

				# ans[ICMP][i][1].show()

				# response from a hop, can be successful or unsuccessful
				resp_src  = ans[ICMP][i][1].src
				resp_dst  = ans[ICMP][i][1].dst
				resp_type = ans[ICMP][i][1].type 


				if resp_type != 0:

					# when the hop decrements the ttl and ttl = 0, this is the packet the hop receibed.
					hop_src   = ans[ICMP][i][1][1].src
					hop_dst   = ans[ICMP][i][1][1].dst
					hop_type  = ans[ICMP][i][1][1].type

				# group times from same host
				if resp_src in d:
					d[resp_src].append(elapsedTime)
				else:
					d[resp_src] = [elapsedTime]

			else:

				failed +=1

		# print output
		print '%s' % ttl,
		print ' *'*failed,

		for key in d:

			try:
				host = socket.gethostbyaddr(key)[0]
			except:
				host = key

			print ' %s (%s)' % (host, resp_src),
			
			for elem in d[key]:
				print " %.3f ms" % elem,


		print ''

		ttl += 1
		failed = 0

	# ans[ICMP][0][1].show()



if __name__ == "__main__":

	if len(sys.argv) > 1:
		url = sys.argv[1]
	else:
		url = 'google.com'

	myTraceRoute(url)