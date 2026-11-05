package autoaddclientgo

import (
	"fmt"
	"path/filepath"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"
)

// Manage_Auto_ADD_client installe l'agent sur une machine distante par SSH.
//
// hostip accepte « adresse » ou « adresse:port ». Sans port, 22 est employé —
// le comportement d'avant, qui était alors le seul possible.
//
// # Pourquoi le port était un problème
//
// Les trois étapes ci-dessous passaient 22 en dur. Une machine dont sshd écoute
// ailleurs — configuration courante, et recommandée par bien des guides de
// durcissement — était donc injoignable, avec pour seul indice :
//
//	ssh-keyscan failed: exit status 1 | Stderr:
//
// Un stderr vide, parce que ssh-keyscan ne dit rien quand il ne trouve
// personne. Rien dans ce message ne désignait le port, et rien ne suggérait
// qu'il pût être en cause.
func Manage_Auto_ADD_client(hostuser, hostip, client_softwareID string) string {
	hote, port, err := SeparerHoteEtPort(hostip)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: cible invalide "+hostip+": "+err.Error())
		return "cible invalide : " + err.Error()
	}

	privateKeyPath, err := duckykey.GetLoginClientPrivateKeyPath()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertLoad, "autoadd: login client SSH key from database failed: "+err.Error())
		return "error: " + err.Error()
	}

	// Empreinte de la clé publique du core, déposée dans le répertoire que le
	// SCP ci-dessous recopie sur la machine.
	//
	// Elle voyage ainsi par SSH — un canal authentifié — et non par la trame
	// « askkey », que rien n'authentifie. C'est ce décalage de canal qui donne
	// sa valeur à l'empreinte : l'agent pourra vérifier la clé qu'il recevra
	// plus tard au lieu de l'accepter sur parole.
	//
	// L'échec n'interrompt PAS l'installation. Un agent sans empreinte
	// fonctionne — il accepte la première clé, en le signalant dans son
	// journal. Refuser d'installer pour autant transformerait un durcissement
	// en panne de déploiement, ce qui pousserait à le contourner.
	repertoireClient := filepath.Join(storage.Client_Conf_path, "clientsoftware", client_softwareID)
	if err := duckykey.EcrireEmpreintePourClient(repertoireClient); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeCertLoad,
			"autoadd: empreinte du core non déposée pour "+client_softwareID+" : "+err.Error()+
				" — l'agent acceptera la première clé reçue")
	}

	// La clé de signature des politiques (TO-DO 52), au même endroit et sur le
	// même canal.
	//
	// C'est le SEUL moment où elle peut être posée : la faire demander par
	// l'agent au core reviendrait à lui faire apprendre d'un core la clé qui
	// sert à juger ce que ce core envoie.
	//
	// Même règle que l'empreinte pour l'échec : une machine sans cette clé ne
	// vérifie pas les signatures et fonctionne comme avant. Refuser d'installer
	// transformerait un durcissement en panne de déploiement.
	if err := duckykey.EcrireClePolitiquePourClient(repertoireClient); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeCertLoad,
			"autoadd: clé de signature des politiques non déposée pour "+client_softwareID+" : "+
				err.Error()+" — l'agent ne vérifiera pas les signatures de politique")
	}

	// La clé de signature des PAQUETS d'agent (TO-DO 113) : même canal, même
	// raison — c'est elle qui jugera un jour les mises à jour que le core
	// ordonnera, elle ne peut donc pas venir de lui en route. Même règle pour
	// l'échec : une machine sans elle s'installe, et refusera toute mise à
	// jour automatique jusqu'à ce qu'on la lui dépose.
	if err := duckykey.EcrireClePaquetsPourClient(repertoireClient); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeCertLoad,
			"autoadd: clé de signature des paquets non déposée pour "+client_softwareID+" : "+
				err.Error()+" — la machine refusera toute mise à jour automatique")
	}

	// La liste des CORES à joindre (TO-DO 61), dans le même répertoire.
	//
	// Le script d'installation écrivait une adresse fixe, en dur. Elle vient
	// maintenant du cluster : tous les cores exposés, dans l'ordre de la 04_04.
	// Même règle que l'empreinte : un échec n'empêche pas l'installation, le
	// script se rabat sur l'adresse du core qui l'exécute.
	if n, errConf := EcrireConfClient(database.GetDatabase(), repertoireClient); errConf != nil {
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"autoadd: liste des cores non écrite pour "+client_softwareID+" : "+errConf.Error()+
				" — le script d'installation prendra l'adresse de ce core")
	} else if n == 0 {
		logs.Write_Log("WARNING", "autoadd: aucun core exposé et en ligne pour "+client_softwareID+
			" — le script d'installation prendra l'adresse de ce core")
	} else {
		logs.Write_Log("INFO", fmt.Sprintf("autoadd: %d core(s) écrit(s) dans %s pour %s", n, NomConfClient, client_softwareID))
	}

	// Une seule connexion pour les trois étapes, clé d'hôte vérifiée (et
	// apprise la première fois) : voir transport_ssh.go.
	client, err := connexionSSH(hostuser, privateKeyPath, hote, port)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection,
			fmt.Sprintf("autoadd: connexion SSH à %s port %d impossible : %s", hote, port, err.Error()))
		return err.Error()
	}
	defer client.Close()

	if err := envoyerFichiersClient(client, client_softwareID); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: send file to host "+client_softwareID+" failed: "+err.Error())
		return "error send file: " + err.Error()
	}
	if err := ExecuterCommandesSSHAvecCle(client, hote); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: execute commands on host "+client_softwareID+" failed: "+err.Error())
		return "error execute commands: " + err.Error()
	}
	return ("new client setup remotly with succes with this ID : " + client_softwareID)
}
