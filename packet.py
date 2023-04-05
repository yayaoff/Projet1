import pyshark as ps
import dns.resolver

def read_file_pcap_filter(filename,filter):
    return ps.FileCapture(filename)

def get_infos(file_capture):
    lst = {}
    dom_serv = {}
    print(file_capture[0])
    for pckt in file_capture:
        name = pckt.dns.qry_name
        time = pckt.sniff_time
        if(name not in lst):
            lst[name] = [time]
            if 'DNS' in pckt and pckt.dns.qry_name == name:
                 server_authoritative = pckt.dns.resp_name
                 dom_serv[name] = server_authoritative
            # try:
            #     dom_serv[name] = dns.resolver.resolve(name, 'NS')
            # except:
            #     dom_serv[name] = {'No Serv'}
            #print("New domain name found : " + str(name))
        elif(name in lst):
            lst[name].append(time)
    return (lst,dom_serv)

def print_dict(d):
    for key in d.keys():
        print('\n')
        print(key + ' :')
        for value in d[key]:
            print(value)

f1 = read_file_pcap_filter("test1.pcapng",'dns')
f2 = read_file_pcap_filter("test2.pcapng",'dns')
f3 = read_file_pcap_filter("test3.pcapng",'dns')
f4 = read_file_pcap_filter("test4.pcapng",'dns')
f5 = read_file_pcap_filter("test5.pcapng",'dns1')
f6 = read_file_pcap_filter("test6.pcapng",'dns')

infos1 = get_infos(f1)
dict1_1 = infos1[0]
dict1_2 = infos1[1]
#print_dict(t1)
print("Total of domain names for test file 1: " + str(len(dict1_1.keys())))
print_dict(dict1_2)


# tot = get_infos(f)
# 
# print_dict(tot)

f1.close()