import os
#pip3 install google
from googlesearch import search
#pip3 install ioc_finder
from ioc_finder import find_iocs
import json
#pip3 install pyattck
from pyattck import Attck


print("""
'########::'##::::'##:'########::'########::'##:::::::'########::::::::::'########:'########::::'###::::'##::::'##::
 ##.... ##: ##:::: ##: ##.... ##: ##.... ##: ##::::::: ##.....:::::::::::... ##..:: ##.....::::'## ##::: ###::'###::
 ##:::: ##: ##:::: ##: ##:::: ##: ##:::: ##: ##::::::: ##::::::::::::::::::: ##:::: ##::::::::'##:. ##:: ####'####::
 ########:: ##:::: ##: ########:: ########:: ##::::::: ######:::'#######:::: ##:::: ######:::'##:::. ##: ## ### ##::
 ##.....::: ##:::: ##: ##.. ##::: ##.....::: ##::::::: ##...::::........:::: ##:::: ##...:::: #########: ##. #: ##::
 ##:::::::: ##:::: ##: ##::. ##:: ##:::::::: ##::::::: ##::::::::::::::::::: ##:::: ##::::::: ##.... ##: ##:.:: ##::
 ##::::::::. #######:: ##:::. ##: ##:::::::: ########: ########::::::::::::: ##:::: ########: ##:::: ##: ##:::: ##::
..::::::::::.......:::..:::::..::..:::::::::........::........::::::::::::::..:::::........::..:::::..::..:::::..:::
""")
print("\n**************************************************************************")
print("\n*     Copyright of Godwine Papin HOUNGAVOU, 2021  _*_Blacksnow_*_        *")
print("\n*     Sup De Vinci, M1 Cybersécurité - Projet Professionnel              *")
print("\n*  Ce projet est disponible en licence GNU General Public License v3.0   *")
print("\n*     https://github.com/godwineHoungavou/ProjetPro_Supdevinci_M1CBS     *")
print("\n**************************************************************************")

print("\nBienvenue dans cet outil d'automatisation des actions PURPLE TEAM!\n\nVeuillez choisir une action à mener.")

condition = True
while condition:
    action = input("""1) Recherche OSINT sur un domaine stratégique (GOOGLE DORKS)
2) WHOIS grabbing
3) Recherche d'email sur une cible
4) Recherche de fichier sur une cible
5) Recherche de nom de domaines et sous-domaines sur une cible
6) Collecte des IOC d'une menace
7) Collecte du modèle MITRE ATTCK d'une menace
    \n""")

    print("Vous avez sélectionné: ", action)

    if action == '1':
        while condition:
            dork = input("""1) Recherche de mot de passe utilisateur sur un domaine
2) Recherche des informations financière sur un domaine
3) Utilisation d'une chaîne de recherche spéciale pour trouver des sites Web vulnérables ou des vulnérabilités sur un site
4) Trouver des redirections ouvertes  \n""")

            #On commence le traitement pour la recherche des documents sur le domaine spécifié
            if dork == '1':
                domaine = input("\nSaississez le domaine cible: ")
                print("\nLancement de la recherche des fichiers sur le domaine(pdf, xls, pptx, docs...)... Patientez!!!")
                query = f"site:{domaine} intitle:Index of /password.txt,Index of /password,Index of passwd,Index of /admin"
                for i in search(query, pause=5):
                    print(i)
                condition = False

            elif dork == '2':
                domaine = input("\nSaississez le domaine cible: ")
                print("\nLancement de la recherche des fichiers financial sur le domaine... Patientez!!!")
                query = f"site:{domaine} intitle:index.of finances.xls intitle:Index of finance.xls"
                for i in search(query, pause=5):
                    print(i)
                condition = False

            elif dork == '3':
                domaine = input("\nSaississez le domaine cible (Vous pouvez laisser le domaine vide pour rechercher des domaines vulnérables): \n")
                print("\nLancement de la recherche des vulnérabilités sur le domaine... Patientez!!!")
                query = f"site:{domaine} inurl: php?id=,gallery.php?id=,article.php?id=,show.php?id=,staff_id=,newsitem.php?,trainers.php?id=,buy.php?category=,article.php?ID=,play_old.php?id=,declaration_more.php?decl_id=,pageid=,games.php?id=,page.php?file=,newsDetail.php?id=,gallery.php?id=,article.php?id=,show.php?id=,staff_id=,newsitem.php?num="
                for i in search(query, pause=5):
                    print(i)
                condition = False

            elif dork == '4':
                domaine = input("\nSaississez le domaine cible: ")
                print("\nLancement de la recherche des redirections ouvertes sur le domaine... Patientez!!!")
                query = f"site:{domaine} inurl:url=https,url=http,u=http,u=http,redirect?https,redirect?http,redirect=https,redirect=http,link=http,link=https"
                for i in search(query, pause=5):
                    print(i)
                condition = False

            else:
                print("\nChoix incorrect! Reéssayez!\n")

        #condition = False
        break;

#On lance la recherche des informations publiques sur le domaine grace à l'outil WHOIS
    elif action == '2':
        #On demande à l'utilisateur de saisir le nom de doamine
        domaine = input("\nEntrez le nom du domaine sur lequel vous recherchez des informations (Ex: exemple.com): ")
        print("\n\nLancement... Collecte des informations en cours, patientez...!\n")
        #On exécute la commande whois qui effectue des recherches sur le nom de domaine en se basant sur des informations issues de base de données publiques
        os.system(f"whois {domaine}")
        #L'Affichage des résultats de la commande est automatique puisqu'il s'agit d'une commande système directement exécutée.
        condition = False
        break;

#On commence la recherche des adresses emails sur le domaine fournit par l'utilisateur
    elif action == '3':
        #On demande à l'utilisateur de saisir le domaine pour lequel on recherchera les emails
        domaine = input("\nEntrez le domaine cible pour la recherche des emails (Ex: exemple.com): ")
        print("\n\nLancement...Recherche des emails en cours, patientez...!")
        print("\nListe des emails découverts sur la cible: ", domaine, "\n")
        #On lance la recherche des emails grace à l'outil theHarvester. On effectue la recherche sur plusieurs sources afin d'obtenir plus de résultats
        os.system(f"theHarvester -d {domaine} -l 1000 -b baidu,bing,bingapi,bufferoverun,certspotter,crtsh,dnsdumpster,duckduckgo,exalead,google,hackertarget,linkedin,netcraft,omnisint,otx,qwant,rapiddns,sublist3r,threatcrowd,threatminer,trello,twitter,urlscan,virustotal,yahoo|grep '@' | grep -v '* cmartorella@edge-security.com'")
        print("\n")
        condition = False
        break;
    #On commence la recherche des fichiers sur un domaine spécifique
    elif action == '4':
        #L'utilisateur saisie le nom du domaine cible
        domaine = input("\nSaississez le domaine cible: ")
        print("\nLancement de la recherche des fichiers sur le domaine(pdf, xls, pptx, docs...)...Patientez!!!")
        #On définit la requete google à effectuer
        query = f"site:{domaine} inurl:doc,pdf,xls,txt,ps,rtf,odt,sxw,psw,ppt,pps,xml filetype:doc,pdf,xls,txt,ps,rtf,odt,sxw,psw,ppt,pps,xml"
        #On lance la requete et on récupère chaque résultat qu'on affiche
        for i in search(query, pause=5):
            print(i)

        condition = False
        break;

    elif action == '5':
        #On demande à l'utilisateur de saisir le nom de domaine
        domaine = input("\nEntrez le nom de domaine cible (Ex: exemple.com): ")
        print("\nRecherche en cours...Veuillez patienter...!")
        #On lance la recherche des sous domaines grace à l'outil sublist3r. Pour l'intsaller: apt-get install sublist3r
        #On exécute la commande et on sauvegarde le résultat dans un fichier temporaire et on désactive l'Affichage du resultat de la commande dans la console
        os.system(f"sublist3r -d {domaine} -o {domaine}.txt > nul 2>&1")
        print("\n________________Les domaines et sous-domaines découverts________________\n")
        #On affiche le resultat de la commande
        os.system(f"cat {domaine}.txt")
        print("\n")

        condition = False
        break;

#On commence la collecte des indicateurs de compromission. L'utilisateur entre un texte duquel on extrait les potentiels indicateurs de compromission.
    elif action == '6':
        #On utilise l'outil ioc_finder pour le traitement. Pour son installation: pip3 install ioc-finder
        text = input("\nSaississez ou collez ci-après le texte ou contenus du fichier log à partir duquel les indicateurs de compromission seront analysés: \n")
        #On récupère tous les IOC trouvés dans le texte
        iocs =  find_iocs(text)
        print("\nRecherche des IOC en cours...Patientez!!!\n")
        print("\nLes indicateurs de compromission (IOC) collectés sont:\n")
        #On affiche les indicateurs trouvés
        print("IOC (Indicator Of Compromise)\t\t\t\t\tValeurs\n--------------------------------------------------------------------")
        for i in iocs:
            print("{:29}    {}".format(i, iocs[i]))

        condition = False
        break;

    elif action == '7':
        attack = Attck()
        cadre = input("\nEntrez le cadre MITRE ATTCK que vous souhaitez collecter parmis les cadres suivants: ENTREPRISE, PRE-ATTCK et MOBILE: ")
        while (cadre != 'ENTREPRISE' and cadre != 'PRE-ATTCK' and cadre != 'MOBILE'):
            cadre = input("\nCadre incorrect...Reéssayez en respectant la casse (Ex: ENTREPRISE, PRE-ATTCK et MOBILE): ")

        if cadre == 'ENTREPRISE':
            #Tactique, technique, Mitigation
            print("\n--------\t\tLes tactiques utilisées pour le Mitre Attck ENTREPRISE\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tTactique\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for tactic in attack.enterprise.tactics:
                print("{:50}    {}".format(tactic.name, tactic.wiki))

            print("\n\t################################################################################\n")
            print("\n--------\t\tLes techniques utilisées pour le Mitre Attck ENTREPRISE\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tTechniques\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for technique in attack.enterprise.techniques:
                print("{:50}    {}".format(technique.name, technique.wiki))

            print("\n\t################################################################################\n")
            print("\n--------\t\tLes mitigations utilisées pour le Mitre Attck ENTREPRISE\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tMitigation\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for mitigation in attack.enterprise.mitigations:
                print("{:50}    {}".format(mitigation.name, mitigation.wiki))

        elif cadre == 'PRE-ATTCK':
            #Tactique, technique, Mitigation
            print("\n--------\t\tLes tactiques utilisées pour le Mitre Attck PRE-ATTCK\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tTactique\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for tactic in attack.preattack.tactics:
                print("{:50}    {}".format(tactic.name, tactic.wiki))

            print("\n\t################################################################################\n")
            print("\n--------\t\tLes techniques utilisées pour le Mitre Attck PRE-ATTCK\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tTechniques\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for technique in attack.preattack.techniques:
                print("{:50}    {}".format(technique.name, technique.wiki))


            print("\n\t################################################################################\n")
            print("\n--------\t\tLes acteurs utilisées pour le Mitre Attck PRE-ATTCK\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tNom d'acteur\t\t\t\t\t\t    \t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for actor in attack.preattack.actors:
                print(actor.name)

        elif cadre == 'MOBILE':
            #Tactique, technique, Mitigation
            print("\n--------\t\tLes tactiques utilisées pour le Mitre Attck MOBILE\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tTactique\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for tactic in attack.mobile.tactics:
                print("{:50}    {}".format(tactic.name, tactic.wiki))
                #print(tactic.name)

            print("\n\t################################################################################\n")
            print("\n--------\t\tLes techniques utilisées pour le Mitre Attck MOBILE\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tTechniques\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for technique in attack.mobile.techniques:
                print("{:50}    {}".format(technique.name, technique.wiki))

            print("\n\t################################################################################\n")
            print("\n--------\t\tLes mitigations utilisées pour le Mitre Attck MOBILE\t---------")
            print("-------------------------------------------------------------------------------------------------")
            print("|\tMitigation\t\t\t\t\t\t Lien\t\t\t\t|")
            print("-------------------------------------------------------------------------------------------------")
            for mitigation in attack.mobile.mitigations:
                print("{:50}    {}".format(mitigation.name, mitigation.wiki))

        condition = False
        break;
    else:
        print("Choix incorrect. Reéssayer!\n")
