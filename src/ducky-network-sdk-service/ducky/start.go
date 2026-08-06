package ducky

import (
	"duckynetworkclient/V1/config"
	"duckynetworkclient/V1/duckynetwork/enrollment"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	serveurcommunication "duckynetworkclient/V1/serveur_communication"
	"duckynetworkclient/V1/sessionmgr"
	"fmt"
	"time"
)

// Start ouvre une session Ducky et rend la main une fois le client authentifié.
//
// Enchaîne, sans que l'appelant ait à s'en occuper :
//
//	enrôlement (01_05 → 01_08) si aucune identité n'existe encore
//	connexion au premier serveur qui répond
//	askkey si la clé publique du core manque
//	01  le défi qui authentifie LE SERVEUR
//	02  l'authentification du programme auprès de lui
//
// # Pourquoi attendre l'authentification avant de rendre la main
//
// La connexion et la poignée de main sont asynchrones : la boucle de réception
// tourne dans sa propre goroutine, et c'est elle qui reçoit le 02_04 ou 02_11
// final. Rendre la main dès la connexion TCP donnerait à l'appelant une session
// qui a l'air ouverte mais que le core refusera à la première trame utile — avec
// un message qui ne dira pas que le login manque.
func Start(opts Options) (*sessionmgr.Session, error) {
	if err := opts.prepare(); err != nil {
		return nil, err
	}
	if err := ensureIdentity(opts); err != nil {
		return nil, err
	}

	// EnableServerCommunication ne rend pas la main tant que la connexion vit :
	// elle porte la boucle de réception. D'où la goroutine — et d'où l'attente
	// juste après, seul moyen de savoir si elle a abouti.
	go serveurcommunication.EnableServerCommunication(opts.Username, opts.Password)

	session, err := waitAuthenticated(opts.Timeout)
	if err != nil {
		return nil, err
	}
	logs.Write_log("INFO", "session Ducky établie (id="+session.SessionID+")")
	return session, nil
}

// ensureIdentity garantit qu'une identité et une paire de clés sont en place.
//
// # Les deux doivent aller ensemble
//
// Une identité sans clé privée ne sert à rien : la poignée de main 01_02 arrive
// chiffrée avec la clé publique enregistrée côté core, et personne ne saurait la
// lire. On réenrôle donc dans ce cas plutôt que de laisser le service échouer
// en boucle sur un déchiffrement qui n'aboutira jamais.
func ensureIdentity(opts Options) error {
	known, err := config.LoadClientSoftware()
	if err != nil {
		return err
	}
	if known && keymanagement.HasClientKeys() {
		return nil
	}

	switch {
	case known:
		logs.Write_log("WARNING",
			"identité présente mais clé privée absente : réenrôlement nécessaire")
	default:
		logs.Write_log("INFO", "aucune identité locale : enrôlement nécessaire")
	}

	if !opts.Enroll {
		return fmt.Errorf(
			"aucune identité utilisable dans %s et enrôlement non autorisé "+
				"(mettre Enroll à true, ou déployer client_software.yaml et private_key.pem)",
			opts.KeyPath)
	}
	if _, err := enrollment.Enroll(); err != nil {
		return fmt.Errorf("enrôlement : %w", err)
	}
	return nil
}

// waitAuthenticated attend qu'une session de service soit authentifiée.
//
// Le scrutin plutôt qu'un canal : l'état est publié dans le gestionnaire de
// sessions par la boucle de réception, qui ne connaît pas l'appelant. Y ajouter
// une notification demanderait de faire remonter un canal à travers quatre
// paquets, pour un gain nul à cette échelle de temps.
func waitAuthenticated(timeout time.Duration) (*sessionmgr.Session, error) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s := stosession.SessionsUser.GetValidVaultaireSession(); s != nil {
				return s, nil
			}
		case <-deadline:
			return nil, fmt.Errorf(
				"aucune session authentifiée après %s : vérifiez que le core est joignable "+
					"et que la clé publique enregistrée côté core est bien celle de ce service",
				timeout)
		}
	}
}

// Current rend la session de service en cours, ou nil.
func Current() *sessionmgr.Session {
	return stosession.SessionsUser.GetValidVaultaireSession()
}
