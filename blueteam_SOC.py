#!/usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import json
import time
import pyhibp
from pyhibp import pwnedpasswords as pw
import pprint

print("""
'########::'##:::::::'##::::'##:'########:'########:'########::::'###::::'##::::'##:::::::::::'######:::'#######:::'######:::
 ##.... ##: ##::::::: ##:::: ##: ##.....::... ##..:: ##.....::::'## ##::: ###::'###::::::::::'##... ##:'##.... ##:'##... ##::
 ##:::: ##: ##::::::: ##:::: ##: ##:::::::::: ##:::: ##::::::::'##:. ##:: ####'####:::::::::: ##:::..:: ##:::: ##: ##:::..:::
 ########:: ##::::::: ##:::: ##: ######:::::: ##:::: ######:::'##:::. ##: ## ### ##:'#######:. ######:: ##:::: ##: ##::::::::
 ##.... ##: ##::::::: ##:::: ##: ##...::::::: ##:::: ##...:::: #########: ##. #: ##:........::..... ##: ##:::: ##: ##::::::::
 ##:::: ##: ##::::::: ##:::: ##: ##:::::::::: ##:::: ##::::::: ##.... ##: ##:.:: ##::::::::::'##::: ##: ##:::: ##: ##::: ##::
 ########:: ########:. #######:: ########:::: ##:::: ########: ##:::: ##: ##:::: ##::::::::::. ######::. #######::. ######:::
........:::........:::.......:::........:::::..:::::........::..:::::..::..:::::..::::::::::::......::::.......::::......::::
""")
print("\n**************************************************************************")
print("\n*     Copyright of Godwine Papin HOUNGAVOU, 2021  _*_Blacksnow_*_        *")
print("\n*     Sup De Vinci, M1 Cybersécurité - Projet Professionnel              *")
print("\n*     https://github.com/godwineHoungavou/ProjetPro_Supdevinci_M1CBS     *")
print("\n**************************************************************************")

#La clé API de virusTotal
API_key = '36b4dc2152a103997961b8f57bf58a28e35728908c3fc30b2d70b94dfeeef61e'

#on demande à l'utilisateur de choisir l'action à mener.
condition = True

print("\nBienvenue dans cet outil d'automatisation Blue Team d'analyse SOC Red Team!\n\nVeuillez choisir une action à mener.")
while condition:
    action = input("""\n1) Analyser une URL
2) Analyser un fichier
3) Analyser la signature d'un fichier
4) Vérifier si votre email est en violation de données
5) Vérifier si votre mot de passe est en violation de données \n""")

    print("Vous avez sélectionné: ", action)

    if action == '1':
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        link = input("\nSaississez l'URL à scanner au format (https://exemple.com): ")
        parameters = {'apikey': API_key, 'resource': link}
        response= requests.get(url, params=parameters)
        json_response= json.loads(response.content)
        while (json_response['response_code'] <= 0):
            link = input("\nL'URL est incorrect...Reéssayez. Saississez l'URL: ")
        if json_response['response_code'] >= 1:
            if json_response['positives'] <= 0:
                print(f"\nL'URL: {link} n'est pas malveillant. \n")
            else:
                print(f"\nL'URL: {link} est malveillant et a été détecté par {str(json_response['positives'])} solutions\n")
        time.sleep(15)

        condition = False
        break;

    elif action == '2':
        fichier = input("\nSaississez le chemin absolu du fichier à analyser (Ex: /root/Bureau/test/script.sh): ")

        url = 'https://www.virustotal.com/vtapi/v2/file/scan'

        params = {'apikey': API_key}

        files = {'file': (fichier, open(fichier, 'rb'))}

        response = requests.post(url, files=files, params=params)
        json_response = response.json()
        #pprint.pprint(json_response)

        if json_response['response_code'] == 0:
            print("\nAucun fichier trouvé\n")
        elif json_response['response_code'] == 1:
            #On récupère le hash SHA1 du fichier et on analyse le hash
            file_hsh = json_response['sha1']
            url1 = 'https://www.virustotal.com/vtapi/v2/file/report'
            parame = {'apikey': API_key, 'resource': file_hsh}
            response1 = requests.get(url1, params=parame)
            json_response1 = response1.json()

            if json_response1['positives'] == 0:
                print("\nLe fichier n'est pas malveillant\n")
            else:
                print(f"\nLe fichier est malveillant et a été détecté avec {str(json_response1['positives'])} solutions \n")
        else:
            print("\Impossible de faire l'analyse. Reéssayez plus tard!\n")

        condition = False
        break;

    #On commence l'analyse du hash du fichier
    elif action == '3':
        #L'utilisateur saisie le hash à analyser
        hsh = input("\nSaississez le hash de votre fichier (Ex: d41d8cd98f00b204e9800998ecf8427e): ")
        #On vérifie si la taille du hash correspond à celle des hashs habituels
        while (len(hsh) != 32 and len(hsh) != 40 and len(hsh) != 64):
            hsh = input("\nLe hash saisi est invalide...Reéssayez! Entrez le hash: ")

        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': API_key, 'resource': hsh}
        response = requests.get(url, params=params)
        json_response = response.json()

        if json_response['response_code'] == 0:
            print("\nAucune correspondance trouvée pour ce hash\n")
        elif json_response['response_code'] == 1:
            if json_response['positives'] <= 0:
                print("\nLe hash du fichier n'est pas malveillant\n")
            else:
                print(f"\nLe hash du fichier est malveillant et a été détecté avec {str(json_response['positives'])} solutions \n")
        else:
            print("\Impossible de faire l'analyse. Reéssayez plus tard!\n")

        condition = False
        break;
    elif action == '4':
        email = input("\nSaississez l'adresse email à vérifier: ")
        #rate = 1.3
        server = "haveibeenpwned.com"
        sslVerify = True
        #sleep = rate
        check = requests.get("https://"+server+"/api/v2/breachedaccount/" + email + "?includeUnverified=true", verify = sslVerify)
        if str(check.status_code) == "404":
            #L'adresse email n'a pas été victime d'une fuite de données
            print("\n L'adresse email n'a pas été violée ou été dans une fuite de données")
        elif str(check.status_code) == "200":
            #L'adresse email a été violée
            print("\nL'adresse email a été violée")
        else:
            #print(check.status_code)
            print("\nUne erreur s'est produite: This version of the API has been discontinued, please use V3: https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/!!! ")

        condition = False
        break;
    elif action == '5':
    #On définit un agent utilisateur décrivant l'application utilisant l'API HIBP
        pyhibp.set_user_agent(ua="Awesome application/0.0.1 (An awesome description)")
        #L'utilisateur saisit le mot de passe
        passw = input("\nSaississez le mot de passe à vérifier: ")
        #Vérifiez si le mot de passe n'a été divulgué dans une violation publique
        resp = pw.is_password_breached(password=passw)
        if resp:
            print("\nVotre mot de passe a déjà fuité!")
            print("Ce mot de passe a été utilisé {0} fois déjà.".format(resp))
        else:
            print("\nVotre mot n'a pas été violée ou été dans une fuite de données")

        condition = False
        break;
    else:
        print("\nChoix incorrect! Reéssayez!\n")
