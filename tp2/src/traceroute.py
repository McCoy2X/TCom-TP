#! /usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
from subprocess import *
from pyx import *
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
import math
from sets import Set
import networkx as nx
from geoip import geolite2
import pycountry

HOP_LIMIT = 30
REPEAT_REQ = 5
DEGREE = 2 # polinomial degree used to detect transatlantic cables

# Scapy: http://www.secdev.org/projects/scapy/doc/usage.html
# ICMP: http://www.ietf.org/rfc/rfc792.txt

def myTraceRoute(url):
	
	try:
		host = socket.gethostbyname(url)
	except:
		print "%s: Name or service not known" % url
		return

	print "traceroute to %s (%s), 20 hops max" % (url, host)

	data  = list()
	edges = Set()

	ttl = 1;
	resp_type = -1

	addr_from = '192.168.0.9'
	addr_to   = ''

	while resp_type != 0 and ttl <= HOP_LIMIT:

		d = dict() # key as ip to group same ip RTTs
		failed = 0
		
		pck = IP(dst=url, ttl=ttl) / ICMP()

		for _ in range(0, REPEAT_REQ):

			ans, unans = sr(pck, timeout=1, verbose=0)

			if len(ans) > 0: # got answers!

				sent = datetime.fromtimestamp(ans[0][0].sent_time)
				received = datetime.fromtimestamp(ans[0][1].time)
				elapsedTime = (received-sent).total_seconds()*1000

				i = 0

				# the request my computer sends to the url
				# req_src  = ans[i][0].src
				# req_dst  = ans[i][0].dst
				# req_type = ans[i][0].type

				# response from a hop, can be successful or unsuccessful
				resp_src  = ans[i][1].src
				resp_dst  = ans[i][1].dst
				resp_type = ans[i][1].type 

				# if resp_type != 0:

				# 	# when the hop decrements the ttl and ttl = 0, this is the packet the hop receibed.
				# 	hop_src   = ans[i][1][1].src
				# 	hop_dst   = ans[i][1][1].dst
				# 	hop_type  = ans[i][1][1].type

				# group times from same host
				if resp_src in d:
					d[resp_src].append(elapsedTime)
				else:
					d[resp_src] = [elapsedTime]

				addr_to = resp_src
				edges.add((addr_from, addr_to))
				addr_from = addr_to

			else:

				failed += 1

		# print trace
		print '%s' % ttl,
		print ' *'*failed,

		if failed > 0:
			data.append((ttl, ' *'*failed, 0))

		for key in d:

			host, country, continent = getHostData(key)

			print ' %s (%s)' % (host, resp_src),
			
			for elem in d[key]:
				print " %.3f ms" % elem,

			if country is not None:
				print " (%s, %s)" % (country, continent),

			# save data
			data.append((ttl, key, d[key]))

		print ''

		ttl += 1
		failed = 0

	# print ans.pdfdump('packets.pdf', layer_shift=1)
	return data

def getHostData(ip):

	# get hostname
	try:
		host = socket.gethostbyaddr(ip)[0]
	except:
		host = ip

	# get country data
	match = geolite2.lookup(ip)

	if match is not None:
		country = match.country
		continent = match.continent
	else:
		country = None
		continent = None

	return (host, country, continent)

def printLatexTable(data):

	print "Hop & Avg. RTT & IP Address & Host name & Location\\\\ \\midrule"

	for ttl, ip, rtts in data:
		if rtts == 0:
			print "%s & %s &  &  &  \\\\" % (ttl, ip)
		else:

			host, country, continent = getHostData(ip)

			print "%s & %s ms & %s & %s & %s, %s\\\\" % (ttl, np.mean(rtts), ip, host, country, continent)

def detectIntercontinentalHops(data):

	findOutlier = True

	while findOutlier:

		x = list()
		y = list()

		for ttl, ip, rtts in data:

			if rtts == 0: # * * * *
				continue

			x.append(ttl)
			y.append(np.mean(rtts)) # list of averages

		x = np.array(x)
		y = np.array(y)

		coefs = np.polyfit(x, y, DEGREE)
		p = np.poly1d(coefs)

		df = len(x) - (DEGREE + 1)
		residuals = y - np.polyval(coefs, x)

		se = math.sqrt(np.sum(np.square(residuals)) / df)
		std_residuals = residuals / se

		xp = np.linspace(1, max(x), 100)
		plt.figure(1)
		plt.subplot(211)
		plt.plot(x, y, '.', xp, p(xp), '-')
		plt.ylim(ymin=0)
		plt.xlabel('Hops')
		plt.ylabel('Time (ms)')

		plt.subplot(212)
		plt.plot(x, std_residuals, '.')
		plt.axhline(y=0, xmin=0, xmax=max(x), hold=None)
		plt.xlabel('Hops')
		plt.ylabel('Standarized Residual')

		plt.show()

		std_residuals = np.absolute(std_residuals);
		outlier = max(std_residuals)
		time    = y[np.where(std_residuals == outlier)]

		print x
		print y
		print "Standarized residuals:"
		print std_residuals

		if outlier > 2: # passes first test

			for row in data:
				ttl, ip, rtts = row
				if time == np.mean(rtts):
					print "Hop %s (%s) is intercontinental." % (ttl, ip)
					data.remove(row)
					break

		else:

			findOutlier = False

def stackedBoxPlot(data, name):

	hosts = list()
	rtt  = list()
	error = list()

	for ttl, ip, rtts in reversed(data):

		if rtts == 0:
			continue

		host, country, continent = getHostData(ip)

		country = pycountry.countries.get(alpha2=country)

		hosts.append(ip + "\n" + country.name);
		rtt.append(np.mean(rtts))
		error.append(2*np.std(rtts))

	y_pos = np.arange(len(hosts)) + 1

	plt.barh(y_pos, rtt, xerr=error, align='center', height=0.8, alpha=0.4)
	plt.yticks(y_pos, hosts, horizontalalignment='right', fontsize=9)
	plt.xlabel('RTT (ms)')
	plt.ylim(ymin=0)
	plt.ylabel('Host')
	plt.savefig('../docs/images/'+url+'.png', bbox_inches='tight')
	plt.show()

if __name__ == "__main__":

	if len(sys.argv) > 1:
		url = sys.argv[1]
	else:
		url = 'www.google.com'

	data = myTraceRoute(url)
	stackedBoxPlot(data, url)
	detectIntercontinentalHops(data)
	printLatexTable(data)