import pyshark as ps

def read_file_pcap_filter(filename,filter):
    return ps.FileCapture(filename, display_filter=filter)

def get_infos(file_capture):
    lst = {}
    for pckt in file_capture:
        if 'DNS' in pckt:
            name = pckt.dns.qry_name
            time = pckt.sniff_time
            if(name not in lst):
                lst[name] = [time]
                #print("New domain name found : " + str(name))
            elif(name in lst):
                lst[name].append(time)
    return lst

def print_dict(d):
    for key in d.keys():
        print('\n')
        print(key + ' :')
        for value in d[key]:
            print(value)

f = read_file_pcap_filter("paquet_test.pcapng",'dns.flags.response == 1')
tot = get_infos(f)
print("Total of domain names : " + str(len(tot)))
print_dict(tot)
f.close()