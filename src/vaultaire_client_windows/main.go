// Agent Vaultaire pour Windows — V1.
//
// # Ce que fait cette version, et ce qu'elle ne fait pas
//
//	FAIT      enrôlement et tunnel Ducky, comme un poste Linux
//	FAIT      authentification d'un utilisateur du domaine par mot de passe
//	FAIT      provisionnement du compte Windows local correspondant
//	FAIT      liste des cores et proxies : découverte (04_04), ordre servi,
//	          persistance de la liste apprise, repli sur la configuration
//	FAIT      inventaire, battement, versions déclarées au core
//	IGNORÉ    les GPO : les trames sont reçues, journalisées, non appliquées
//	IGNORÉ    les révocations : même traitement
//	ABSENT    SSH, clés publiques, groupes du domaine — pas de sshd ici
//
// # L'architecture, en deux processus
//
//	LogonUI.exe ─ VaultaireCredentialProvider.dll ─┐
//	                                     tube nommé│  (\\.\pipe\vaultaire_agent)
//	                     vaultaire_client_windows ─┘── tunnel Ducky ── core
//
// Le Credential Provider est une DLL COM chargée par l'écran de connexion de
// Windows. Elle ne parle pas au réseau : elle pose une question sur un tube
// nommé, et l'agent — un service, qui tourne en SYSTEM et détient l'identité de
// la machine — y répond. C'est le découpage de tous les fournisseurs
// d'identité tiers, et il tient à une raison : ce qui plante dans LogonUI fait
// disparaître l'écran de connexion de la machine.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/decouverte"
	duckytool "duckynetworkclient/V1/duckynetwork/ducky_tool"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"

	"vaultaire_client/config"
	serveurcommunication "vaultaire_client/serveur_communication"
	yamlvaultaire "vaultaire_client/yaml"

	"vaultaire_client_windows/auth"
	"vaultaire_client_windows/gpo"
	"vaultaire_client_windows/version"
)

// RacineParDefaut : tout l'état de l'agent, en un seul endroit.
//
// %ProgramData% et non %ProgramFiles% : le répertoire des programmes est en
// lecture seule pour un service qui doit écrire son identité et ses journaux.
// Et pas %AppData% : l'agent tourne en SYSTEM, sans profil utilisateur.
const RacineParDefaut = `C:\ProgramData\Vaultaire`

func main() {
	racine := flag.String("racine", RacineParDefaut,
		"répertoire d'état : configuration, identité, journaux")
	cheminConfig := flag.String("config", "",
		"fichier de configuration (défaut : <racine>\\client_conf.json)")
	afficherVersion := flag.Bool("version", false, "afficher la version et sortir")
	console := flag.Bool("console", false,
		"forcer le mode console même lancé comme service (diagnostic)")
	flag.Parse()

	if *afficherVersion {
		fmt.Println(version.Info().Complete())
		fmt.Println("socle :", version.SDK().Complete())
		return
	}

	poserChemins(*racine)

	fichier := *cheminConfig
	if fichier == "" {
		fichier = filepath.Join(*racine, "client_conf.json")
	}

	if err := demarrer(fichier); err != nil {
		// Sur la sortie d'erreur ET dans le journal : lancé à la main, personne
		// ne lit le journal ; lancé comme service, personne ne voit la console.
		fmt.Fprintln(os.Stderr, "vaultaire :", err)
		logs.Write_log("CRITICAL", "démarrage impossible : "+err.Error())
		os.Exit(1)
	}

	servir(*console)
}

// poserChemins place l'état de l'agent sous la racine Windows.
//
// Les valeurs par défaut du socle sont celles d'un poste Linux
// (/etc/vaultaire_client/.ssh, /var/log/vaultaire). Elles sont posées ICI,
// avant toute écriture : la première ligne de journal crée déjà son répertoire.
func poserChemins(racine string) {
	storage.KeyPath = filepath.Join(racine, "keys")
	storage.SoftwarePath = filepath.Join(racine, "client_software.yaml")
	storage.LogPath = filepath.Join(racine, "logs") + string(filepath.Separator)
	// Un nom PROPRE à ce binaire : l'agent Linux écrit vaultaire_client.log, et
	// partager le nom rendrait une rétention par entité impossible le jour où
	// les deux journaux se retrouvent dans un même dépôt de collecte.
	storage.NomJournal = "vaultaire_client_windows.log"
}

// demarrer branche le socle, lit la configuration et ouvre le tunnel.
func demarrer(cheminConfig string) error {
	brancherSocle()

	if err := config.LoadConfig(cheminConfig); err != nil {
		return fmt.Errorf("configuration illisible (%s) : %w", cheminConfig, err)
	}
	if len(config.AdressesConnues()) == 0 {
		return fmt.Errorf("aucun core déclaré dans %s : l'agent ne saurait à qui parler", cheminConfig)
	}
	// L'identité de la machine, créée sur le core par « vlt create -c » et
	// déposée par install.ps1. Sans elle, l'agent ne peut rien faire du tout :
	// on s'arrête ici plutôt que d'ouvrir un canal qui refuserait toutes les
	// connexions sans dire pourquoi.
	if !yamlvaultaire.ReadYAMLFile(storage.SoftwarePathResolu()) {
		return fmt.Errorf("identité de la machine illisible (%s) : "+
			"créez-la sur le core avec « vlt create -c <nom> » et déposez "+
			"client_software.yaml et private_key.pem sur ce poste",
			storage.SoftwarePathResolu())
	}

	logs.Write_log("INFO", fmt.Sprintf("agent Windows %s — état dans %s",
		version.Info().Complete(), filepath.Dir(cheminConfig)))
	logs.Write_log("INFO", "cores et proxies connus : "+strings.Join(config.AdressesConnues(), ", "))

	// Le tunnel machine, dès le démarrage et non à la première connexion : une
	// machine sur laquelle personne ne se connecte doit quand même apparaître
	// dans `vlt status -c`, recevoir sa liste de nœuds et déclarer sa version.
	serveurcommunication.DemarrerTunnelMachine()

	brancherDecouverte()
	return nil
}

// brancherSocle raccorde l'agent au socle Ducky.
//
// À appeler EN PREMIER : la boucle de réception consulte le registre des
// gestionnaires dès la connexion établie, et une catégorie branchée après coup
// laisserait passer sans traitement les trames arrivées entre-temps.
func brancherSocle() {
	// L'agent reste connecté et se reconnecte : c'est ce que Persistent décide.
	storage.Persistent = true
	// La version part dans l'inventaire 02_12, émis dès l'authentification :
	// posée après, le premier inventaire l'annoncerait vide.
	storage.VersionComposant = version.Info().Complete()

	// La boucle de connexion de l'AGENT, et non celle du socle : elle lit
	// client_conf.json (JSON), là où le socle attend du YAML. Elle est
	// idempotente — une authentification qui trouve le tunnel en cours de
	// rétablissement ne lance pas une seconde boucle.
	duckytool.DemarrerSessionMachine = serveurcommunication.DemarrerTunnelMachine

	tramesmanager.RegisterHandler("03", auth.HandleTrame03)
	tramesmanager.RegisterHandler("04", decouverte.HandleTrame)
	// 05 et 06 sont REÇUES et ignorées, volontairement — voir le paquet gpo.
	tramesmanager.RegisterHandler("05", gpo.HandleTrameGPO)
	tramesmanager.RegisterHandler("06", gpo.HandleTrameRevocation)
}

// brancherDecouverte arme la demande périodique de la liste des nœuds.
//
// C'est ce qui donne à l'agent Windows le même comportement de cluster qu'un
// poste Linux : il apprend les cores et proxies annoncés par le core, dans
// l'ORDRE servi (proxies affins, autres proxies, cores affins, autres cores),
// et persiste cette liste pour la retrouver au redémarrage.
func brancherDecouverte() {
	decouverte.Configure(func(trame string) {
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "découverte : aucune session, trame non envoyée")
			return
		}
		sendmessage.SendMessage(trame, session.DuckySession)
	}, storage.Computeur_ID)

	// La liste apprise est persistée dans client_conf.json, section « learned »
	// — le même fichier et le même format que l'agent Linux (TO-DO 61). Seuls
	// les nœuds à empreinte de confiance arrivent ici.
	decouverte.SurNouvelleListe(func(noeuds []decouverte.Noeud) {
		liste := make([]config.ServerConfig, 0, len(noeuds))
		for _, n := range noeuds {
			liste = append(liste, config.ServerConfig{
				IP: n.IP, Port: n.Port, Hostname: n.Hostname, Role: n.Role,
			})
		}
		ecrit, err := config.MettreAJourAppris(liste)
		switch {
		case err != nil:
			logs.Write_log("ERROR", "découverte : liste apprise non persistée : "+err.Error())
		case ecrit:
			logs.Write_log("INFO", fmt.Sprintf("découverte : %d nœud(s) persisté(s) dans %s",
				len(liste), config.Chemin()))
		}
	})

	decouverte.Demarrer(func() string {
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			return ""
		}
		return string(session.DuckySession.SessionKey)
	})
}

// PeriodeBilan : l'agent dit périodiquement ce qu'il a fait.
//
// Sans ce bilan, un agent dont plus personne ne se connecte ne laisse aucune
// trace : on ne peut pas distinguer « aucune tentative » de « plus de journal ».
const PeriodeBilan = 30 * time.Minute

// bilan journalise l'état de l'agent, périodiquement.
func bilan(etat func() (int64, int64)) {
	logs.Go("bilan de l'agent", func() {
		for {
			time.Sleep(PeriodeBilan)
			servies, refusees := etat()
			logs.Write_log("INFO", fmt.Sprintf(
				"bilan : %d requête(s) d'authentification, %d refusée(s) avant le core, "+
					"%d trame(s) de politique ignorée(s), raccordé : %t",
				servies, refusees, gpo.Recues(), auth.Raccorde()))
		}
	})
}
