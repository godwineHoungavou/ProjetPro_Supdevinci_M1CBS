#!/usr/bin/python3
# -*- coding: utf-8 -*-
import nmap
import nmap3
import socket
import ipaddress
import re
import scapy.all as scapy
import os
import pprint



#Initialisation
#On définit un pattern pour le range de port à utiliser plus tard
#Le format est : petitPort-grandPort (ex: 20-125)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
#Initialisation des numero de ports à utiliser plus tard
port_min = 0
port_max = 65535



print("""
'########::'########:'########::'########:'########::::'###::::'##::::'##:::::::::::'######:::'#######:::'######:::
 ##.... ##: ##.....:: ##.... ##:... ##..:: ##.....::::'## ##::: ###::'###::::::::::'##... ##:'##.... ##:'##... ##::
 ##:::: ##: ##::::::: ##:::: ##:::: ##:::: ##::::::::'##:. ##:: ####'####:::::::::: ##:::..:: ##:::: ##: ##:::..:::
 ########:: ######::: ##:::: ##:::: ##:::: ######:::'##:::. ##: ## ### ##:'#######:. ######:: ##:::: ##: ##::::::::
 ##.. ##::: ##...:::: ##:::: ##:::: ##:::: ##...:::: #########: ##. #: ##:........::..... ##: ##:::: ##: ##::::::::
 ##::. ##:: ##::::::: ##:::: ##:::: ##:::: ##::::::: ##.... ##: ##:.:: ##::::::::::'##::: ##: ##:::: ##: ##::: ##::
 ##:::. ##: ########: ########::::: ##:::: ########: ##:::: ##: ##:::: ##::::::::::. ######::. #######::. ######:::
..:::::..::........::........::::::..:::::........::..:::::..::..:::::..::::::::::::......::::.......::::......::::
""")
print("\n**************************************************************************")
print("\n*     Copyright of Godwine Papin HOUNGAVOU, 2021  _*_Blacksnow_*_        *")
print("\n*     Sup De Vinci, M1 Cybersécurité - Projet Professionnel              *")
print("\n*  Ce projet est disponible en licence GNU General Public License v3.0   *")
print("\n*     https://github.com/godwineHoungavou/ProjetPro_Supdevinci_M1CBS     *")
print("\n**************************************************************************")

#on demande à l'utilisateur de choisir l'action à mener.
condition = True

print("\nBienvenue dans cet outil d'automatisation Red Team d'analyse SOC Red Team!\n\nVeuillez choisir une action à mener.")
while condition:
    action = input("""\n1) Network Scanning (Découverte d'IP sur un réseau)
2) Port Scanning sur une IP
3) Host Scanning
4) Banner Grabbing sur un port
5) Analyse de vulnérabilités
6) DNS discovering (DNS Brute Force) \n""")

    print("Vous avez sélectionné: ", action)

    #On fait un switch-case pour éxecuter l'action de l'utilisateur
    #On commence le scan réseau afin de découvrir les hôtes présents sur le réseau
    if action == '1':
        #print("en cours!")
        while True:
            #Saisie de l'adresse IP à scanner par l'utilisateur
            ip_adr_saisie = input("\nEntrez l'adresse IP du réseau à scanner au format (Ex: 192.168.0.1/24): ")
            #On fait un block Try/Except pour vérifier si l'adresse IP saisie respecte la bonne nomenclature des IP
            try:
                #Avec le module ipaddress on vérifie si l'adresse IP est correcte
                ip_adr_check = ipaddress.ip_network(ip_adr_saisie, False)
                break;
            except:
                print("Adresse IP invalide. Reéssayez!")
        #ip_adr_saisie = input("\nEntrez l'adresse IP à scanner: ")
        #Création du packet ARP
        arp_packet = scapy.ARP(pdst=ip_adr_saisie)
        #Création du packet Ether pour le broadcasting. L'adresse MAC utilisé est ff:ff:ff:ff:ff:ff
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        #Faire l'empilation
        broadcast_packet = ether/arp_packet
        #le résultat est une liste de paires au format (sent_packet, received_packet)
        resultat = scapy.srp(broadcast_packet, timeout=3, verbose=0)[0]

        #On crée une liste des clients à récupérer
        clients = []
        for sent, received in resultat:
            #pour chaque réponse, on ajoute l'adresse ip et mac à la liste `clients`
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        #Affichage des résultats
        print("Les hôtes disponibles sur le réseau sont:")
        print("IP\t\t\tMAC\n----------------------------------------")
        for client in clients:
            print("{:16}    {}".format(client['ip'], client['mac']))

        condition = False
        break;

    #On commence le port scanning sur l'IP à saisir (on fait la découverte des ports sur l'hôte ainsi que leur état)
    elif action == '2':
        while True:
            #Saisie de l'adresse IP à scanner par l'utilisateur
            ip_adr_saisie = input("\nEntrez l'adresse IP à scanner: ")
            #On fait un block Try/Except pour vérifier si l'adresse IP saisie respecte la bonne nomenclature des IP
            try:
                #Avec le module ipaddress on vérifie si l'adresse IP est correcte
                ip_adr_check = ipaddress.ip_address(ip_adr_saisie)
                break;
            except:
                print("Adresse IP invalide. Reéssayez!")
        #L'utilisateur saisit la plage de port à scanner sur l'hôte (0-65535 ports)
        print("\nEntrez la plage de port à scanner dans le format suivant: Entier-Entier (Ex: 20-80). Pour scanner un port, entrez n°Port-n°Port (Ex: 25-25)")
        while True:
            port_scan_saisi = input("\nSaississez la plage de ports: ")
            #On supprime les espaces vides saisies par l'utilisateur. S'il saisit 25 - 443, on formate pour avoir 25-443
            port_range_check = port_range_pattern.search(port_scan_saisi.replace(" ",""))
            if port_range_check:
                #On récupère le petit port saisi dans le range
                port_min = int(port_range_check.group(1))
                #On récupère le grand port saisi dans le range
                port_max = int(port_range_check.group(2))
                break;

        scan_res = nmap.PortScanner()
        print("\n")
        #On lance le scan de tous les ports contenus dans le range
        for port in range(port_min, port_max + 1):
            try:
                #On récupère le résultat du scan par nmap. Ce résultat correspond à la commande nmap : nmap -oX - -p PORT -T4 -A -v IP_adresse
                result = scan_res.scan(ip_adr_saisie, str(port), '-T4 -A -v')
                #print(result)

                #On extrait l'état du port de l'objet retourner dans le resultat par nmap
                port_etat = (result['scan'][ip_adr_saisie]['tcp'][port]['state'])
                print(f"Le port {port} est {port_etat}")
            except:
                #Quand certains ports ne peuvent pas être scannés, pour éviter que le programme crash, on affiche un message d'erreur
                print(f"Impossible de scanner le port: {port}.")

        condition = False
        break;


#On commence le traitement du host scanning
    elif action == '3':
        while True:
            #Saisie de l'adresse IP à scanner par l'utilisateur
            ip_adr_saisie = input("\nEntrez l'adresse IP à scanner: ")
            #On fait un block Try/Except pour vérifier si l'adresse IP saisie respecte la bonne nomenclature des IP
            try:
                #Avec le module ipaddress on vérifie si l'adresse IP est correcte
                ip_adr_check = ipaddress.ip_address(ip_adr_saisie)
                break;
            except:
                print("Adresse IP invalide. Reéssayez!")
        print("\n Analse des services et du système d'exploitation en cours...Patientez!!!\n\n")
        os.system(f'nmap -O -v {ip_adr_saisie}| tail -n +3 | head -n -2')

        condition = False
        break;



#On commence le traitement pour le banner grabbing
    elif action == '4':
        while True:
            #Saisie de l'adresse IP à grabber par l'utilisateur
            ip_adr_saisie = input("\nEntrez l'adresse IP à grabber: ")
            #On fait un block Try/Except pour vérifier si l'adresse IP saisie respecte la bonne nomenclature des IP
            try:
                #Avec le module ipaddress on vérifie si l'adresse IP est correcte
                ip_adr_check = ipaddress.ip_address(ip_adr_saisie)
                break;
            except:
                print("Adresse IP invalide. Reéssayez!")
        #L'utilisateur saisit la plage de port à grabber sur l'hôte (0-65535 ports)
        print("\nEntrez la plage de port à grabber dans le format suivant: Entier-Entier (Ex: 20-80). Pour grabber un port, entrez n°Port-n°Port (Ex: 25-25)")
        while True:
            port_scan_saisi = input("\nSaississez la plage de ports: ")
            #On supprime les espaces vides saisies par l'utilisateur. S'il saisit 25 - 443, on formate pour avoir 25-443
            port_range_check = port_range_pattern.search(port_scan_saisi.replace(" ",""))
            if port_range_check:
                #On récupère le petit port saisi dans le range
                port_min = int(port_range_check.group(1))
                #On récupère le grand port saisi dans le range
                port_max = int(port_range_check.group(2))
                break;

        scan_res = nmap.PortScanner()
        s = socket.socket()
        #On définit la durée pour la connexion. On met 1s pour que le socket fasse la connexion au port
        s.settimeout(1)
        print("\n")
        #On lance le grabbing de tous les ports contenus dans le range
        for port in range(port_min, port_max + 1):
            try:
                #On récupère le résultat du scan par nmap. Ce résultat correspond à la commande nmap : nmap -oX - -p PORT -sV IP_adresse
                result = scan_res.scan(ip_adr_saisie, str(port), '-T4 -A -v')
                #On extrait le nom du service qui tourne sur port de l'objet retourner dans le resultat par nmap
                port_serv_name = (result['scan'][ip_adr_saisie]['tcp'][port]['name'])
                #On extrait la version du service qui tourne sur port de l'objet retourner dans le resultat par nmap
                port_serv_version = (result['scan'][ip_adr_saisie]['tcp'][port]['version'])
                #On extrait le nom du produit qui tourne sur port de l'objet retourner dans le resultat par nmap
                port_serv_produit = (result['scan'][ip_adr_saisie]['tcp'][port]['product'])
                print(f"Le port {port} tourne le service {port_serv_name} ,version: {port_serv_produit} {port_serv_version}")

                #On crée la connexion à l'adresse IP via le socket
                try:
                    s.connect((ip_adr_saisie,  port))
                    #Si la ligne précédente s'exécute avec succès alors le port est ouvert.
                    print(f"\nInformations supplémentaires grabbées sur le port {port}: \n  {s.recv(1024).decode('utf-8')}")
                except:
                    pass
            except:
                print(f"Impossible de grabber le port {port}. ")

        condition = False
        break;

    elif action == '5':
        while True:
            #Saisie de l'adresse IP à scanner par l'utilisateur
            ip_adr_saisie = input("\nEntrez l'adresse IP à analyser: ")
            #On fait un block Try/Except pour vérifier si l'adresse IP saisie respecte la bonne nomenclature des IP
            try:
                #Avec le module ipaddress on vérifie si l'adresse IP est correcte
                ip_adr_check = ipaddress.ip_address(ip_adr_saisie)
                break;
            except:
                print("Adresse IP invalide. Reéssayez!")

        #resul = bash_exec('nmap -sV --script vulners --script-args mincvss=5.0 -oN output.txt %s' %ip_adr_saisie)
        print(f"\nAnalyse des vulnérabilités en cours sur l'hôte {ip_adr_saisie} ......\n")
        os.system('nmap -sV --script vulners http-vulners-regex --script-args mincvss=5.0  %s | tail -n +3 | head -n -2' %ip_adr_saisie)

        condition = False
        break;

    #Traitement du DNS brute forcing pour la découverte de tous les hostnames présents
    elif action == '6':
        while True:
            #Saisie de l'adresse du host à scanner par l'utilisateur
            fqdn_saisie = input("\nEntrez l'adresse du host à analyser (Ex: exemple.com): ")
            #On fait un block Try/Except pour vérifier si le domaine saisie respecte la bonne nomenclature des FQDN
            try:
                #Avec le module ipaddress on vérifie si l'adresse IP est correcte
                fqdn_check = validators.domain(fqdn_saisie)
                break;
            except:
                print("Nom de demaine invalide. Reéssayez!")
        #fqdn_saisie = input("\nEntrez l'adresse du host à analyser (Ex: exemple.com): ")
        #On lance le script nmap pour effectuer le brute force dns sur le nom de domaine
        nmap = nmap3.Nmap()
        fqdn_discover = nmap.nmap_dns_brute_script(fqdn_saisie)
        print("Adresse IPv4/IPv6\t\t\tNom de domaine\n---------------------------------------------------------")
        #Le résultat renvoyé est au format JSON alors on parcourt les données JSON puis on les affiche.
        for p in fqdn_discover:
            print("{:32}    {}".format(p["address"], p["hostname"]))

        condition = False
        break;


    #traitement des erreurs pour la saisie du numero d'action.
    else:
        print("\nChoix incorrect! Reéssayez!\n")
