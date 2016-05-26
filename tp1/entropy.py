import math
import csv
import time

files = ["plaza", "dc"]
totalFiles = 2
alias = dict({'34525': 'IPv6', '2054': 'ARP', '2048': 'IPv4'})

for i in xrange(totalFiles):
    dataTest = dict()
    dataProbabilities = []
    entropy = 0
    totalPackets = 0
    
    with open('resultados/' + files[i] + '_s1.csv', 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=",")
        
        for row in reader:
            if alias[row[1]] in dataTest:
                dataTest[alias[row[1]]] = dataTest[alias[row[1]]] + 1
            else:
                dataTest[alias[row[1]]] = 1
            totalPackets +=1

    dataItems = dataTest.items()
    print dataItems
        
    with open('datosProcesados/' + files[i] + '_s1.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        
        for key, value in dataItems:
            dataProbabilities.append((key, value/float(totalPackets)))
            writer.writerow([key] + [value])

    print dataProbabilities

    with open('datosProcesados/' + files[i] + '_inf_s1.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        
        for key, prob in dataProbabilities:
            entropy += float(prob) * math.log(1/prob)
            writer.writerow([key] + [math.log(1/prob)])

    print entropy

    with open('datosProcesados/' + files[i] + '_s1_entropy.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        writer.writerow([entropy])