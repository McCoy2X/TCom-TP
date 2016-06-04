#! /usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import sys
from subprocess import *
from pyx import *
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
import math
from sets import Set
from geoip import geolite2
import pycountry
from scipy import stats

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
		sys.exit()

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
		# host = ""
		host = ip

	# get country data
	match = geolite2.lookup(ip)

	if match is not None:
		country = match.country
		continent = match.continent
		country = pycountry.countries.get(alpha2=country).name
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

			print "%s & %s ms & %s & %s & %s\\\\" % (ttl, np.mean(rtts), ip, host, country)

def detectIntercontinentalHops(data):

	data = [row for row in data if row[2] != 0] # remove *s

	findOutlier = True

	edges = list()

	for i in range(0, len(data)-1):

		from_ttl, from_ip, from_rtts = data[i]
		to_ttl, to_ip, to_rtts       = data[i+1]

		elapsedTime = np.mean(to_rtts) - np.mean(from_rtts)

		if elapsedTime <= 0: continue

		edges.append((from_ttl, to_ttl, elapsedTime, from_ip, to_ip))

	selectedEdges = list()

	while findOutlier:

		x = list()

		for edge in edges:
			x.append(edge[2])

		mean = np.mean(x)
		S    = np.std(x)

		abs_dev = map(abs, x-mean)

		outlier_candidate = max(abs_dev)

		index = abs_dev.index(outlier_candidate)
		time  = x[index]

		# print "candidate: %s, mean: %s, std: %s, index: %s, time: %s" % (outlier_candidate, mean, std, index, time)

		n = len(x)
		alpha = 0.05
		t_critical = stats.t.ppf(1-alpha/2, n-2)

		tao = t_critical * (n-1) / (math.sqrt(n) * math.sqrt(n-2+t_critical**2))

		# print "n: %s" % n
		# print "mean: %s, std: %s" % (mean, S)
		# print "sample: %s" % x
		# print "abs_dev: %s" % abs_dev
		# print "tao: %s" % tao
		# print "outlier_candidate: %s, tao * S: %s" % (outlier_candidate, tao*S)

		if outlier_candidate > tao * S:

			for edge in edges:
				from_ttl, to_ttl, elapsedTime, from_ip, to_ip = edge
				if time == elapsedTime:
					selectedEdges.append(edge)
					edges.remove(edge)
					if elapsedTime > 10:
						print "Edge (%s, %s) is intercontinental (%s ms)" % (from_ttl, to_ttl, elapsedTime)
					break
		else:
			findOutlier = False

	return selectedEdges

def stackedBoxPlot(data, name):

	hosts = list()
	rtt  = list()
	error = list()

	for ttl, ip, rtts in reversed(data):

		if rtts == 0:
			continue

		host, country, continent = getHostData(ip)

		hosts.append(ip + "\n" + country);
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

def edgesTable(data, selectedEdges):

	data = [row for row in data if row[2] != 0] # remove *s

	edges = list()

	for i in range(0, len(data)-1):

		from_ttl, from_ip, from_rtts = data[i]
		to_ttl, to_ip, to_rtts       = data[i+1]

		elapsedTime = np.mean(to_rtts) - np.mean(from_rtts)

		edges.append((from_ttl, to_ttl, elapsedTime, from_ip, to_ip))

	print "Id & From & To & Avg. RTT & Simbala & GeoIP\\\\ \\midrule"

	row_id = 1

	for edge in edges:

		from_ttl, to_ttl, elapsedTime, from_ip, to_ip = edge
		from_host, from_country, from_continent = getHostData(from_ip)
		to_host, to_country, to_continent = getHostData(to_ip)

		if elapsedTime < 0:
			elapsedTime = "-"

		if from_host != "":
			temp = from_host.split(".")
			from_host = temp[-3] + "." + temp[-2] + "." + temp[-1]

		if to_host != "":
			temp = to_host.split(".")
			to_host = temp[-3] + "." + temp[-2] + "." + temp[-1]

		simbala = 'yes' if edge in selectedEdges else 'no'
		geoCheck = 'yes' if from_continent != to_continent else 'no'

		print "%s & \\parbox[t][1.3cm]{5cm}{%s \\\\ %s, %s \\\\ %s} & \\parbox[t][1.3cm]{5cm}{%s \\\\ %s, %s \\\\ %s} & %s ms & %s & %s\\\\ \\bottomrule" % (row_id, from_ip, from_country, from_continent, from_host, to_ip, to_country, to_continent, to_host, elapsedTime, simbala, geoCheck)
		row_id += 1

if __name__ == "__main__":

	if len(sys.argv) > 1:
		url = sys.argv[1]
	else:
		url = 'www.google.com'

	data = myTraceRoute(url)
	stackedBoxPlot(data, url)
	selectedEdges = detectIntercontinentalHops(data)
	# edgesTable(data, selectedEdges)
	# print '*'*10
	# printLatexTable(data)