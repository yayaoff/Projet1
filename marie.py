import pyshark
import os
import matplotlib.pyplot as plt
import numpy as np

n_tcp = []
n_udp = []
n_other = []
for file in os.listdir("data/"):
    capture = pyshark.FileCapture("data/" + file, display_filter="(tls) && (quic) && (tcp) && !(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883) ")
    capture.load_packets()
    udp = 0
    tcp = 0
    other = 0
    for packet in capture :
        if packet.transport_layer == "UDP":
            udp +=1
        elif packet.transport_layer == "TCP":
            tcp +=1
        else :
            other +=1
    
    n_tcp.append(tcp)
    n_udp.append(udp)
    n_other.append(other)

barWidth = 0.4
br1 = np.arange(len(n_tcp))
br2 = [x + barWidth for x in br1]
br3 = [x + barWidth for x in br2]
 
# Make the plot
plt.bar(br1, n_tcp, color ='orange', width = barWidth,
        edgecolor ='grey', label ='TCP')
plt.bar(br2, n_udp, color ='g', width = barWidth,
        edgecolor ='grey', label ='UDP')
plt.bar(br3, n_other, color ='b', width = barWidth,
        edgecolor ='grey', label ='Other')
 
# Adding Xticks
plt.xlabel('Fonctionnalités', fontweight ='bold', fontsize = 25)
plt.ylabel('Nombre de paquets échangés', fontweight ='bold', fontsize = 25)
plt.xticks([r + barWidth for r in range(len(n_tcp))],
        ['Appel vidéo', "Chat \n dans l'appel", 'Chat', 'Réactions', 'Enregistrement', "Partage \n d'écran", 'Tableau \n blanc'], fontsize = 20)
 
plt.legend(fontsize=25)
plt.savefig('comp_udp.png')
plt.show()