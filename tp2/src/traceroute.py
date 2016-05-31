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


# Dependencies
# pyx, networkx
# pip install python-geoip
# sudo pip install python-geoip-geolite2
# sudo apt-get install python-mpltoolkits.basemap

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

	print "traceroute to %s (%s), 20 hops max" % (url, host)

	data  = dict()
	edges = Set()
	exportTable = list()
	# latitude = list() # wanted to plot all coords on a 'hackish' looking map, failed to import lib :(
	# longitude = list()

	hops = 1
	ttl = 1;
	resp_type = -1
	repeat = 5

	addr_from = '192.168.0.9'
	addr_to   = ''

	while resp_type != 0 and hops <= 40:

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

				addr_to = resp_src
				edges.add((addr_from, addr_to))
				addr_from = addr_to

				# ans[ICMP][0][1].show()

			else:

				failed += 1

		# print output
		print '%s' % ttl,
		print ' *'*failed,

		if failed > 0:
			exportTable.append((ttl, ' *'*failed, "-", "-"))

		for key in d:

			try:
				host = socket.gethostbyaddr(key)[0]
			except:
				host = key

			print ' %s (%s)' % (host, resp_src),
			
			for elem in d[key]:
				print " %.3f ms" % elem,

			match = geolite2.lookup(key)

			# latitude.append(match.location[0])
			# longitude.append(match.location[1])

			if match is not None:
				print " (%s, %s)" % (match.country, match.continent),

			# save data for intercontinental detection
			data[key] = (ttl, np.mean(d[key]))

			exportTable.append((ttl, host, np.mean(d[key]), key))


		print ''

		hops += 1
		ttl += 1
		failed = 0

	# printGraph(edges)

	print "Hop & Avg. RTT & IP Address & Host name & Location\\\\ \\midrule"
	for row in exportTable:
		if row[3] == "-":
			print "%s & %s &  &  &  \\\\" % (row[0], row[1])
		else:
			match = geolite2.lookup(row[3])

			if match is not None:
				country = match.country
				continent = match.continent
			else:
				country = ""
				continent = ""

			print "%s & %s ms & %s & %s & %s, %s\\\\" % (row[0], row[2], row[3], row[1], country, continent)

	# print ans[ICMP].pdfdump('packets.pdf',layer_shift=1)
	return data


def printGraph(edges):

	i = 0
	ids = dict()

	for e in edges:
		if e[0] not in ids:
			ids[e[0]] = i
			i += 1
		if e[1] not in ids:
			ids[e[1]] = i
			i += 1


	G = nx.Graph()

	# for j in range(0, i+1)
	# 	G.add_node(j)

	labels = {}
	for e in edges:
		edge_from = ids[e[0]]
		edge_to   = ids[e[1]]
		
		# labels
		try:
			host_from = socket.gethostbyaddr(e[0])[0]
		except:
			host_from = e[0]

		try:
			host_to = socket.gethostbyaddr(e[1])[0]
		except:
			host_to = e[1]

		if e[0] == '192.168.0.9':
			host_from = 'origin'

		labels[edge_from] = host_from
		labels[edge_to]   = host_to

		G.add_node(edge_from)
		G.add_node(edge_to)
		G.add_edge(edge_from, edge_to)


	pos = nx.spring_layout(G) # positions for all nodes
	nx.draw(G, pos)
	nx.draw_networkx_labels(G, pos, labels, font_size=16)

	plt.show()

def detectIntercontinentalHops(data):

	degree = 2

	findOutlier = True

	while findOutlier:

		x = list()
		y = list()
		t = list()

		for key in data:
			ttl = data[key][0]
			t.append(ttl)

			x.append(ttl)
			y.append(data[key][1]) # list of averages

			# for elem in data[key][1]:
			# 	x.append(ttl);
			# 	y.append(elem);

		x = np.array(x)
		y = np.array(y)
		coefs = np.polyfit(x, y, degree)
		p = np.poly1d(coefs)

		df = len(x) - (degree + 1)
		residuals = y - np.polyval(coefs, x)

		se = math.sqrt(np.sum(np.square(residuals)) / df)
		std_residuals = residuals / se

		# xp = np.linspace(1, max(t), 100)
		# plt.figure(1)
		# plt.subplot(211)
		# plt.plot(x, y, '.', xp, p(xp), '-')
		# plt.xlabel('Hops')
		# plt.ylabel('Time (ms)')

		# plt.subplot(212)
		# plt.plot(x, std_residuals, '.')
		# plt.xlabel('Hops')
		# plt.ylabel('Standarized Residual')

		plt.show()

		std_residuals = np.absolute(std_residuals);
		outlier = max(std_residuals)
		time    = y[np.where(std_residuals == outlier)]

		if outlier > 1.7: # passes first test

			for key in data:
				if time == data[key][1]:
					print "Hop %s (%s) is intercontinental." % (data[key][0], key)
					del data[key]
					break

		else:

			findOutlier = False

if __name__ == "__main__":

	if len(sys.argv) > 1:
		url = sys.argv[1]
	else:
		url = 'www.google.com'

	data = myTraceRoute(url)
	detectIntercontinentalHops(data)

	# network topology!