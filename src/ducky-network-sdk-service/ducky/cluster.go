package ducky

import (
	"time"

	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	tramesmanager "duckynetworkclient/V1/duckynetwork/trames_manager"
)

// Raccordement d'un service au cluster (catégorie 04).
//
// # Pourquoi ici plutôt que dans le binaire du proxy
//
// Le proxy ne contient aucune trame, et c'est la propriété qui a de la valeur :
// le jour où le protocole est durci, il en bénéficie sans qu'une ligne n'y soit
// écrite. Ce fichier tient donc le raccordement, et le proxy le demande en une
// ligne.
//
// Cela vaudra aussi pour tout service futur qui doit être joignable — le
// mécanisme n'a rien de propre au proxy.

// OptionsCluster décrit comment ce service veut exister dans le cluster.
type OptionsCluster struct {
	// Role est écrit tel quel dans cluster_nodes : « proxy », « api »…
	//
	// Seuls « core » et « proxy » sont annoncés aux agents. Un rôle inconnu
	// enregistre le nœud pour la supervision sans le distribuer — ce qui est le
	// comportement voulu d'un service qui n'a pas à recevoir de connexions
	// d'agents.
	Role string

	// Domaine sert à rattacher le nœud à un groupe côté core.
	Domaine string

	// Port sur lequel ce service écoute le protocole Ducky.
	//
	// SANS DÉFAUT, volontairement. Une valeur devinée serait annoncée à tout le
	// parc, et les agents s'y connecteraient sans que rien n'écoute — un délai
	// d'attente par machine, pour un port que personne n'a choisi.
	Port int

	// CadenceBattement espace deux 04_07. Zéro prend le défaut du paquet.
	CadenceBattement time.Duration

	// Decouvrir fait aussi DEMANDER la liste des nœuds joignables.
	//
	// Un proxy en a besoin : il doit savoir vers quels cores relayer. Un service
	// qui ne relaie rien n'a aucune raison de la demander, et le laisser à faux
	// lui évite d'apprendre des empreintes qu'il n'utilisera jamais.
	Decouvrir bool
}

// RejoindreCluster enregistre ce service dans le cluster et l'y maintient.
//
// À appeler APRÈS Start : l'enregistrement voyage sur une session authentifiée,
// et l'émettre avant reviendrait à l'envoyer dans le vide.
//
// # Ce qui n'est PAS fait
//
// Le relais. Ce raccordement rend le service VISIBLE — il apparaît dans
// cluster_nodes, il bat, il est annoncé aux agents s'il en a le rôle. Ce qu'il
// fait ensuite des connexions reçues ne regarde pas ce fichier.
func RejoindreCluster(opts OptionsCluster) error {
	infos, err := decouverte.DecrireNoeudLocal(opts.Role, opts.Domaine, opts.Port)
	if err != nil {
		return err
	}

	// L'émetteur et le fournisseur de clé de session sont les mêmes que côté
	// agent. WaitForVaultaireSession plutôt qu'un simple Get : au moment de
	// l'envoi le tunnel peut être en cours de rétablissement après une coupure,
	// et abandonner ferait perdre un battement — donc risquerait de faire
	// déclarer hors ligne un nœud parfaitement vivant.
	decouverte.Configure(func(trame string) {
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			logs.Write_log("WARNING", "cluster : aucune session valide, trame non envoyée")
			return
		}
		sendmessage.SendMessage(trame, session.DuckySession)
	}, storage.Computeur_ID)

	cleDeSession := func() string {
		session, err := stosession.SessionsUser.WaitForVaultaireSession()
		if err != nil || session == nil || session.DuckySession == nil {
			return ""
		}
		return string(session.DuckySession.SessionKey)
	}

	// Le gestionnaire de catégorie 04 est branché AVANT toute émission : la
	// boucle de réception consulte le registre dès la connexion établie, et une
	// catégorie branchée après coup laisserait passer sans traitement les
	// réponses arrivées entre-temps — dont l'accusé d'enregistrement.
	if !tramesmanager.Handled("04") {
		tramesmanager.RegisterHandler("04", decouverte.HandleTrame)
	}

	decouverte.DemarrerNoeud(cleDeSession, infos, opts.CadenceBattement)

	if opts.Decouvrir {
		decouverte.Demarrer(cleDeSession)
	}
	return nil
}
