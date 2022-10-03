
#
# 2 type protocols can be used: TCP and UDP
# So using these protocols we want to know if the ports are open or closed
#
# TCP and UDP will work in 2 different ways:
# 1) TCP will send a TCP Syn to the target machine if it sends back a SYN-ACK the port is open, it will just be enough to send a RST to cancel the handshake,
# if the target sends back an RST ACK, the port is closed
#
# 2)UDP works in a different way, we send a request to the port of the target machine with UDP, if the machine responds with an ICMP() it means that the port is closed, otherwise if it does not respond it means that the port is open,
# we can use another technique for example for the DNS port to send a DNS request to force the target machine to respond if it does not respond, the port is closed.
#NB: Wait for udp results, waiting time here is longer because we resend packets several times due to packet loss
#
# The script will take 4 parameters:
# 1) The protocol (tcp is chosen by default): --protocol [udp or tcp]
# 2) The IP address: --ip [xxx.xxx.xxx.xxx]
# 3) The port (the range (0-1026) is chosen by default"): --port [x or x-y for a range]
# 4) Show all ports or just open ports (just open ports are selected by default): --verbose
# 5) Display port state reason (by default reasons are not displayed): --reason
#
# Example :
# python main.py --protocole udp --ip 192.168.140.129 --port 0-10 --verbeux
# python main.py --protocole udp --ip 192.168.140.129 --port 53
# python main.py --ip 192.168.140.129 --port 50-53 --verbeux#
# python main.py --ip 192.168.140.129 --port 20-25 --verbeux --reason#
