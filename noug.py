from math import floor
import pyshark
import os
import matplotlib.pyplot as plt


#file = input("Enter file name: ")
file = "appel_22s_Aymeric.pcapng"
file = "Launch_openConvs_Quit_2_aymeric.pcapng"

bin_size = .1 # in ms


capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter="(udp || tcp) && !(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883) ")
capture.load_packets()
print("File: " + str(file) + " has " + str(len(capture)) + " packets")
udp_times = []
tcp_times = []
if (capture.__len__() > 0):
    time_start = float(capture[0].sniff_timestamp)
    time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
    for packet in capture:
        if packet.transport_layer == "UDP":
            udp_times.append(float(packet.sniff_timestamp) - time_start)
        elif packet.transport_layer == "TCP":
            tcp_times.append(float(packet.sniff_timestamp) - time_start)

# graph tcp packets per second
plt.hist(tcp_times, bins=floor((time_end-time_start)/bin_size), label="TCP Packets", color="dark orange")

# graph udp packets per second
plt.hist(udp_times, bins=floor((time_end-time_start)/bin_size), label="UDP Packets", color="light blue")

plt.xlabel('Time (s)')
plt.ylabel('Number of Packets')
plt.title(file + "\nbin size: " + str(bin_size) + "s")

plt.legend(loc='upper right')
plt.show()