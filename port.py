import scapy.all as scapy

adressip = "192.168.1.8"


def scanner(protocole = "tcp", adressip = "192.168.1.8", port = (0,4), verbeux = "ouverts"):
    if protocole == "tcp" :
        ans, unans = scapy.sr(scapy.IP(dst=adressip) / scapy.TCP(dport=port, flags="S"))
        if (verbeux == "ouverts"):
            ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",
                        prn=lambda s, r: r.sprintf("%TCP.sport% is open"))
        else:
            ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",
                        prn=lambda s, r: r.sprintf("%TCP.sport% is open"))
            ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "RA",
                        prn=lambda s, r: r.sprintf("%TCP.sport% is close"))
    elif(protocole == "udp") :
       
if __name__ == '__main__':
    scanner()