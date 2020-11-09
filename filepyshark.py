import pyshark
import pandas as pd
import matplotlib.pyplot as plt

filename = input("Please enter OUTPUT filename with Extension csv/pcap example- file.csv or file.pcap:: ")
try:
    capture = pyshark.LiveCapture(interface="wlan0", output_file=filename)
    capture.sniff()
except KeyboardInterrupt:
    print(capture)
    if len(capture) > 10:
        capture1 = pyshark.FileCapture(filename)
        ip = []
        for pkt in capture1:
            if ("IP" in pkt):
                if ("UDP" in pkt):
                    print(pkt.ip.src, pkt.udp.dstport)
                    ip.append([pkt.ip.src, pkt.udp.dstport])
                elif ("TCP" in pkt):
                    print(pkt.ip.src, pkt.tcp.dstport)
                    ip.append([pkt.ip.src, pkt.tcp.dstport])
            elif ("IPV6" in pkt):
                if ("UDP" in pkt):
                    print(pkt.ipv6.src, pkt.udp.dstport)
                    ip.append([pkt.ipv6.src, pkt.udp.dstport])
                elif ("TCP" in pkt):
                    print(pkt.ipv6.src, pkt.tcp.dstport)
                    ip.append([pkt.ipv6.src, pkt.tcp.dstport])

        data1 = pd.DataFrame(ip, columns=['sourceip', 'port'])
        data1['port'] = data1['port'].astype(int)

        #data1.plot.scatter(x='port', y='sourceip', title='scatter graph')


        #data1 = data1.groupby(['sourceip']).first().plot(kind='line')
        #plt.scatter(data1['sourceip'], data1['port'])
        print( """
        1.plot source IP with port
        1.plot source IP count""")

        con = "y"
        while(con == "y"):
            opt = int(input("Enter the choice:: "))
            if(opt == 1):
                data1_crosstab = pd.crosstab(data1['sourceip'], data1['port'])
                print(data1_crosstab)
                data1_crosstab.plot.bar(stacked=True)
                plt.show()
            elif(opt == 2):
                data1_count = data1['sourceip'].value_counts()
                print(data1_count)
                plot = data1_count.plot(kind='bar')
                # plot = sns.countplot(data1['sourceip'])
                plt.ylim(0, 750)
                y = data1['sourceip'].value_counts()

                for i, v in enumerate(y):
                    plot.text(i - .25, v / y[i] + 5, y[i], fontsize=14)
                plt.show()
            con = input("do you want to continue [y/n]:: ")

        #print(data1)
    else:
        print("[-] YOU HAVE LESS PACKETS TO PLOT THE GRAPH")
