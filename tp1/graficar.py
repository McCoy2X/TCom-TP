import numpy as np
import matplotlib.pyplot as plt

fig = plt.figure()
ax = fig.add_subplot(111)

names = [
        '10.0.0.253',
        '10.2.0.249',
        '10.0.0.241',
        '10.2.1.13',
        '10.2.1.254',
        '10.2.7.254',
        '10.2.1.230',
        '10.2.200.152',
        '10.2.201.130',
        '10.2.203.254',
        ]

## the data
N = 10
menMeans = [
            246,
            251,
            251,
            257,
            288,
            320,
            336,
            418,
            501,
            1568
           ]

## necessary variables
ind = np.arange(N)                # the x locations for the groups
width = 0.6                      # the width of the bars

## the bars
rects1 = ax.bar(ind, menMeans, width,
                color='blue',
                )

# axes and labels
ax.set_xlim(-width/2,len(ind))
ax.set_ylabel('Apariciones en paquetes ARP')
ax.set_title('Direcciones IP')
xTickMarks = names
ax.set_xticks(ind+width/2)
xtickNames = ax.set_xticklabels(xTickMarks)
plt.setp(xtickNames, rotation=45, fontsize=6)

## add a legend
# ax.legend( (rects1[0]), ('Men') )

def autolabel(rects):
    # attach some text labels
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., 1.0001*height,
                '%.2f' % height,
                ha='center', va='bottom')

autolabel(rects1)
fig.savefig('graficos/dc_top_s2.pdf')
plt.close(fig)