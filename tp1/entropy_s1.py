import math
import csv
import time

files = ["plaza", "dc"]
totalFiles = 2

for i in xrange(totalFiles):
    dataTest = dict()
    dataProbabilities = []
    entropy = 0
    totalPackets = 0
    
    with open('resultados/' + files[i] + '_s2.csv', 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=",")
        
        for row in reader:
            if row[0] == '1':
                if row[3] in dataTest:
                    dataTest[row[3]] = dataTest[row[3]] + 1
                else:
                    dataTest[row[3]] = 1
                    
                if row[4] in dataTest:
                    dataTest[row[4]] = dataTest[row[4]] + 1
                else:
                    dataTest[row[4]] = 1
                    
                totalPackets +=2

    dataItems = dataTest.items()
    dataItems.sort(key=lambda tup: tup[1])
    print dataItems
        
    with open('datosProcesados/' + files[i] + '_s2.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        
        for key, value in dataItems:
            dataProbabilities.append((key, value/float(totalPackets)))
            writer.writerow([key] + [value])

    # print dataProbabilities

    with open('datosProcesados/' + files[i] + '_inf_s2.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        
        for key, prob in dataProbabilities:
            entropy += float(prob) * math.log(1/prob)
            writer.writerow([key] + [math.log(1/prob)])

    # print entropy

    with open('datosProcesados/' + files[i] + '_s2_entropy.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        writer.writerow([entropy])