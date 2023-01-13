
from scapy.all import *
import csv
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode

# Read the PCAP file
packets = rdpcap('file.pcap')

# Print the summary info for each packet
with open('savefile.csv', 'w', newline='') as csvfile:
    fieldnames = ['Time', 'Source IP','Source Port', 'Destination','Destination Port','Harmless','Malicious','Suspicious','Undetected']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    
        
    for packet in packets:
        print(packet.summary())
        if packet.summary()[-1] == "w":
            (source,destination) = (packet.summary().split()[5],packet.summary().split()[7])
            print(destination.split(":")[0])
            url=destination.split(":")[0]
            with virustotal_python.Virustotal("<YOUR API KEY>") as vtotal:
                try:
                    resp=vtotal.request("urls", data={"url":url}, method="POST")
                    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                    report = vtotal.request(f"urls/{url_id}")
                    result = report.data['attributes']['last_analysis_stats']
                    print(result)
                except virustotal_python.VirustotalError as err:
                    result = f"Failed to send URL:{url} for analysis and get the report: {err}"
                    
            row = {
                    'Time': packet.time,
                    'Source IP': source.split(":")[0],
                    'Source Port':source.split(":")[1],
                    'Destination': destination.split(":")[0],      
                    'Destination Port': destination.split(":")[1],
                    'Harmless':result['harmless'],
                    'Malicious':result['malicious'],
                    'Suspicious':result['suspicious'],
                    'Undetected':result['undetected']
            }
            writer.writerow(row)