#"Realiser par Ali Basma
#Important : Je n'ai pas les bon resultats lorsque je met 127.0.0.1 comme adresse ip je ne sais pas pourquoi alors que pour tous le reste des adresse ip marche
# Ce script scanne les port d'une machine cibler
#
# 2 type protocoles peuvent etre utiliser : TCP et UDP
# Donc on utilisant c'est protocoles nous souhaitons savoir si les ports sont ouvert ou fermer
#
# TCP et UDP fonctionnerons de 2 maniere differente :
# 1)TCP lui enverra un TCP Syn à la machine cible si celle ci lui renvoie un SYN-ACK c'est que le port est ouvert, il suffira juste de renvoyer un RST pour annuler le Handshake,
# dans le cas ou la cible lui renvoi un RST ACK c'est que le port est fermer
#
# 2)UDP fonctionne d'une differente facon, on envoie une requete au port de la machine cible avec UDP, si la machine repond avec un ICMP() c'est que le port est fermer, sinon sil ne repond pas cest que le port est ouvert,
# nous pouvons utiliser une autre technique par exemple pour le port DNS envoyer une requete DNS pour forcer la machine cible à repondre si celle ci ne repond pas c'est que le port est fermer .
#NB: Patienter pour les resultats de udp, le temps d'attente ici est plus long car nous renvoyons les paquets plusieurs fois dut à la perte de paquet
#
# Le script prendra 4 parametre :
# 1) Le protocole(tcp est choisis par default) : --protocole [udp ou tcp]
# 2) L'adresse IP: --ip [xxx.xxx.xxx.xxx]
# 3) Le port (l'intervalle (0-1026) est choisis par default") : --port [x ou x-y pour un intervalle]
# 4) Afficher tous les ports ou juste les ports ouverts (juste les ports ouverts sont selectionnés par default) : --verbeux
# 5) Afficher la raison de l'etat des ports (par default les raisons ne sont pas afficher) : --reason
#
# Exemple de commande :
# python main.py --protocole udp --ip 192.168.140.129 --port 0-10 --verbeux
# python main.py --protocole udp --ip 192.168.140.129 --port 53
# python main.py --ip 192.168.140.129 --port 50-53 --verbeux#
# python main.py --ip 192.168.140.129 --port 20-25 --verbeux --reason#





import socket
import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser(description= "Scanner de Port \n Exemple : python main.py --ip 192.168.140.129 --port 20-25 --verbeux --reason")
parser.add_argument('--protocole', help=" Type de protocole : TCP ou UDP", default="tcp")
parser.add_argument('--ip', help=" Adresse IP de la machine cible")
parser.add_argument('--port', help=" Le port ou la plage de port à analyser", default="0-1026")
parser.add_argument('--verbeux', help=" Afficher les ports ouverts uniquement ou les ports ouverts et fermer",action="store_true")
parser.add_argument('--reason', help=" Dnne la raison de l'etat de chqaue port",action="store_true")


args = parser.parse_args()





def scanner(protocole, adressip, verbeux, port,reason ):
    if type(port) == tuple:
        intervallePort = range(min(port), max(port)+1)
    else :
        intervallePort = port

    if protocole == "tcp":

        if type(port) == range:
            ans, unans = scapy.sr(scapy.IP(dst=adressip) / scapy.TCP(dport=(min(port), max(port)), flags="S"), timeout = 5, retry = 3)
        else :
            ans, unans = scapy.sr(scapy.IP(dst=adressip) / scapy.TCP(dport=port, flags="S"), timeout = 5, retry = 3)


        if (verbeux == False):
            if(reason == False) :
                ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA", prn=lambda s, r: r.sprintf("%TCP.sport% est ouvert"))
            else :
                ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA", prn=lambda s, r: r.sprintf("%TCP.sport% est ouvert / raison : SYN-ACK "))
        else:
            if(reason == False) :
                ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA", prn=lambda s, r: r.sprintf("%TCP.sport% est ouvert"))
                ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "RA", prn=lambda s, r: r.sprintf("%TCP.sport% est fermer"))
            else :
                ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "SA",prn=lambda s, r: r.sprintf("%TCP.sport% est ouvert / raison : SYN-ACK "))
                ans.summary(lfilter=lambda s, r: r.sprintf("%TCP.flags%") == "RA",prn=lambda s, r: r.sprintf("%TCP.sport% est fermer / raison RST ACK "))

    elif(protocole == "udp") :

        if port == 53 or type(port) == range and 53 in range(min(port), max(port)+1):

            try:
                scapy.sr1(scapy.IP(dst=adressip) / scapy.UDP() / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="www.google.com")))
                reponseDNS = "Le port 53 est ouvert"

            except:
                if verbeux != False:
                    reponseDNS = "le port 53 est fermer"
                else :
                    reponseDNS = ""

        if port != 53 or type(port) == range :
                if type(port) == range :
                    ans, unans = scapy.sr(scapy.IP(dst =adressip) / scapy.UDP(dport = (min(port),max(port))), inter = 2, timeout = 10, retry = 3)

                else:
                    ans, unans = scapy.sr(scapy.IP(dst =adressip) / scapy.UDP(dport = port), inter = 2, timeout = 10, retry = 3)
                if len(ans) == 0 :
                    print("le port " + port + " est ouvert")

                else:
                    portfermer = []

                    for i in range(0,len(ans)) :
                        if ans[i][1].type == 3 :
                            portfermer.append(str(ans[i][1].dport))

                    if type(port) == range:
                        for z in intervallePort:
                            if z != 53 :
                                if str(z) in portfermer :
                                    if verbeux != False:
                                        if reason == False :
                                            print("Le port "+ str(z) + " est fermer")
                                        else :
                                            print("Le port "+ str(z) + " est fermer / raison :ICMP/ Port inaccessible")

                                else:
                                    print("Le port " + str(z) + " est ouvert")
                            else :
                                print(reponseDNS)
                    else:
                            if port != 53:
                                if str(port in portfermer):
                                    if verbeux != False:
                                        if reason == False:
                                            print("Le port " + str(port) + " est fermer")
                                        else:
                                            print("Le port " + str(port) + " est fermer / raison :ICMP/ Port inaccessible")

                                else:
                                    print("Le port " + str(port) + " est ouvert")
        else:
                                print(reponseDNS)

                            #print("Le port "+ str(ans[i][1].dport) + " est fermer")

                        #else:
                         #   print("Le port " + (ans[i][1].dport) + " est ouvert")



if __name__ == '__main__':

    print("!!!! \n"
          "!     !           !                   !\n"
         "!       !          !                   !\n"
        "!         !         !                   !\n"
       "! !!!!!!!!! !        !                   !\n"
      "!             !       !                   !\n"
     "!               !      !!!!!!!!!!!!!       !\n")

    if args.ip != None and  args.ip !='127.0.0.1' :
        protocoleselectionner = args.protocole
        machinecible = args.ip
        typelecture = args.verbeux
        raison = args.reason
        port = args.port.split('-')

        if len(port) == 2  :
            rangeport = range(int(port[0]), int(port[1])+1)
        elif len(port) == 1 :
            rangeport = int(port[0])

        scanner(protocoleselectionner, machinecible, typelecture, rangeport, raison)
    else:
        print("Renseigner une autre adresse ip")

