import pyshark as ps

def read_file_pcap(filename):
    return ps.FileCapture(filename)

print((read_file_pcap("paquet_test.pcapng")))