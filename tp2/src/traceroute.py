#! /usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
from subprocess import *
from pyx import *
from datetime import datetime

# http://www.secdev.org/projects/scapy/doc/usage.html
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
		
		pck = IP(dst=url, ttl=ttl) / ICMP() # 28 bytes

		for _ in range(0,repeat):

			ans, unans = sr(pck, timeout=1, verbose=0)

			if len(ans) > 0: # got answers!

				sent = datetime.fromtimestamp(ans[0][0].sent_time)
				received = datetime.fromtimestamp(ans[0][1].time)
				elapsedTime = (received-sent).total_seconds()*1000

				i = 0

				# the request my computer sends to the url
				# req_src  = ans[ICMP][i][0].src
				# req_dst  = ans[ICMP][i][0].dst
				# req_type = ans[ICMP][i][0].type

				# ans[ICMP][i][1].show()

				# response from a hop, can be successful or unsuccessful
				resp_src  = ans[ICMP][i][1].src
				resp_dst  = ans[ICMP][i][1].dst
				resp_type = ans[ICMP][i][1].type 

				# if resp_type != 0:

				# 	# when the hop decrements the ttl and ttl = 0, this is the packet the hop receibed.
				# 	hop_src   = ans[ICMP][i][1][1].src
				# 	hop_dst   = ans[ICMP][i][1][1].dst
				# 	hop_type  = ans[ICMP][i][1][1].type

				# group times from same host
				if resp_src in d:
					d[resp_src].append(elapsedTime)
				else:
					d[resp_src] = [elapsedTime]


				# ans[ICMP][0][1].show()

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

		# print ans[ICMP].pdfdump('packets.pdf',layer_shift=1)

if __name__ == "__main__":

	if len(sys.argv) > 1:
		url = sys.argv[1]
	else:
		url = 'www.google.com'

	myTraceRoute(url)