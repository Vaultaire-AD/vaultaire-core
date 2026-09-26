package autoaddclientgo

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
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

	// Étape 0 : Ajouter automatiquement le host au known_hosts
	if err := AddHostToKnownHosts(hote, port); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection,
			fmt.Sprintf("autoadd: host key scan failed for %s port %d: %s", hote, port, err.Error()))
		return fmt.Sprintf("host key scan failed for %s port %d : %s", hote, port, err.Error())
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

	err = envoyerFichierSCPAvecCleSSH(hostuser, privateKeyPath, client_softwareID, hote, port)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: send file to host "+client_softwareID+" failed: "+err.Error())
		return "error send file: " + err.Error()
	}
	err = ExecuterCommandesSSHAvecCle(hostuser, privateKeyPath, hote, port)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: execute commands on host "+client_softwareID+" failed: "+err.Error())
		return "error execute commands: " + err.Error()
	}
	return ("new client setup remotly with succes with this ID : " + client_softwareID)
}

// AddHostToKnownHosts ajoute automatiquement la clé du host distant dans ~/.ssh/known_hosts
func AddHostToKnownHosts(host string, port int) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("user error: %v", err)
	}

	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer
	// On force le type de clé pour éviter les lenteurs et on utilise le chemin complet
	cmd := exec.Command("ssh-keyscan", "-p", fmt.Sprintf("%d", port), host)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// ssh-keyscan sort en erreur SANS RIEN ÉCRIRE quand il ne joint
		// personne : le stderr est vide, et le message se réduisait à
		// « exit status 1 | Stderr: ». Rien n'y indiquait quoi vérifier.
		//
		// On complète donc nous-mêmes, puisque nous savons ce qui a été tenté.
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = fmt.Sprintf(
				"aucun message d'erreur — ssh-keyscan n'a pas obtenu de réponse de %s sur le port %d.\n"+
					"  À vérifier, dans cet ordre :\n"+
					"    1. sshd écoute-t-il sur ce port ?   ss -tlnp | grep sshd\n"+
					"    2. le port est-il joignable d'ici ? nc -zv %s %d\n"+
					"    3. un pare-feu le bloque-t-il ?     firewall-cmd --list-ports\n"+
					"  Si sshd écoute sur un autre port, indiquez-le : -join %s:PORT <user>",
				host, port, host, port, host)
		}
		return fmt.Errorf("ssh-keyscan (hôte %s, port %d) a échoué : %v\n  %s", host, port, err, detail)
	}

	// Filtrage pour ne garder QUE les clés (on vire les lignes commençant par #)
	lines := strings.Split(stdout.String(), "\n")
	var cleanOutput strings.Builder
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "#") {
			cleanOutput.WriteString(line + "\n")
		}
	}

	if cleanOutput.Len() == 0 {
		return fmt.Errorf("aucune clé valide trouvée pour %s (stderr: %s)", host, stderr.String())
	}

	// Écriture propre
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(cleanOutput.String()); err != nil {
		return err
	}

	return nil
}
