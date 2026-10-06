package hosthandler

import (
	"database/sql"
	"fmt"
	"strconv"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
	"vaultaire/ducky-network/trame"
)

// Les relais d'un proxy, pilotés par le core — 04_18 → 04_19 (TO-DO 141).
//
//	04_18  proxy → core   compte rendu : ses relais, tels qu'ils tournent
//	04_19  core → proxy   la liste voulue, ou « garde ton fichier », ou rien
//
// # Une trame qui rend compte ET demande
//
// La 04_18 dit au core ce que le proxy fait tourner — c'est ce que la page
// Cluster affiche. La réponse dépend de ce compte rendu : le core ne renvoie
// sa liste que si le proxy ne l'applique pas déjà. Le proxy l'envoie à son
// démarrage, après chaque application, puis chaque minute.
//
// Le core émet aussi une 04_19 de lui-même quand un administrateur vient de
// changer la liste (PousserRelais) : le proxy raccordé à CE core l'applique
// dans la seconde, les autres au compte rendu suivant.
//
// # Ce qu'un proxy ne peut pas faire par cette trame
//
// Changer ce qu'on lui demande. Son compte rendu est gardé à part, et rien de
// ce qu'il contient n'est recopié dans la demande : un proxy compromis peut
// mentir sur son état, pas se donner une configuration.

// Modes d'une 04_19. Écrits aussi dans le SDK (decouverte.Mode…).
const (
	ModeRelaisCore     = "core"
	ModeRelaisFichier  = "fichier"
	ModeRelaisInchange = "inchange"
)

// DecisionPourLeProxy dit quoi répondre à un compte rendu, pour une révision
// demandée (zéro : le core ne pilote pas ce proxy).
//
// Séparée de la base et du réseau pour être éprouvée telle quelle : c'est
// elle qui décide si un proxy rouvre ses ports.
func DecisionPourLeProxy(revision int, rapport clusterstorage.CompteRenduRelais) string {
	if revision == 0 {
		// Le core ne pilote pas. Si le proxy applique encore une liste du
		// core, c'est qu'on vient de lui rendre la main : il doit revenir à
		// son fichier.
		if rapport.Origine == clusterstorage.OrigineCore {
			return ModeRelaisFichier
		}
		return ModeRelaisInchange
	}
	if rapport.Origine == clusterstorage.OrigineCore && rapport.Revision == revision {
		return ModeRelaisInchange
	}
	// Refusée EN ENTIER par le proxy — liste inapplicable, ou proxy qui garde
	// la main. La renvoyer chaque minute ne changerait pas sa réponse et
	// remplirait deux journaux : on attend que la demande change.
	if rapport.RevisionRefusee == revision {
		return ModeRelaisInchange
	}
	return ModeRelaisCore
}

// composerLa0419 écrit la réponse.
func composerLa0419(destination, cleDeSession, mode string, revision int, demande []clusterstorage.RelaisConfig) string {
	if mode != ModeRelaisCore {
		return trame.ReponseClient("04_19", destination, cleDeSession, mode, "0")
	}
	return trame.ReponseClient("04_19", destination, cleDeSession, mode, strconv.Itoa(revision),
		clusterstorage.DemandeRelais{Relais: demande}.Encoder())
}

// handleEtatRelais : 04_18 → 04_19.
func handleEtatRelais(db *sql.DB, t storage.Trames_struct_client, contenu string, session *storage.DuckySession) (string, error) {
	// Le PROPRIÉTAIRE vient de la session, jamais du contenu : un proxy ne
	// rend compte que de lui-même.
	proprietaire, err := clusterdatabase.ProprietaireDepuisSession(session.BoundClientSoftwareID)
	if err != nil {
		logs.Write_Log("SECURITY", "compte rendu de relais refusé : "+err.Error())
		return "", fmt.Errorf("relais : %w", err)
	}

	rapport, err := clusterstorage.DecoderCompteRendu(contenu)
	if err != nil {
		// Répondu « inchangé » plutôt que rien : le proxy n'a rien à corriger
		// de ce qu'il fait tourner, et on ne lui renvoie pas de liste sur la
		// foi d'un état qu'on n'a pas su lire.
		logs.Write_Log("WARNING", fmt.Sprintf("relais : compte rendu de %s illisible, ignoré : %v", proprietaire, err))
		return composerLa0419(t.Destination_Server, t.SessionIntegritykey, ModeRelaisInchange, 0, nil), nil
	}
	if err := clusterdatabase.EnregistrerCompteRendu(db, proprietaire, contenu); err != nil {
		// La vue sera en retard d'un tour ; le pilotage, lui, continue.
		logs.Write_Log("ERROR", "relais : "+err.Error())
	}

	demande, etat, err := clusterdatabase.RelaisDemandes(db, proprietaire)
	if err != nil {
		return "", err
	}
	mode := DecisionPourLeProxy(etat.RevisionDemandee(), rapport)
	if mode == ModeRelaisCore {
		logs.Write_Log("INFO", fmt.Sprintf(
			"relais : révision %d envoyée à %s (il applique la révision %d, origine %s)",
			etat.Revision, proprietaire, rapport.Revision, rapport.Origine))
	}
	return composerLa0419(t.Destination_Server, t.SessionIntegritykey, mode, etat.Revision, demande), nil
}

// PousserRelais envoie tout de suite à un proxy la liste que le core lui
// demande — ou l'ordre de revenir à son fichier.
//
// Rend vrai si la trame est partie. Faux n'est pas une erreur : le proxy
// n'est pas raccordé à CE core, ou il est hors ligne. Il recevra la liste en
// réponse à son prochain compte rendu, une minute au plus après sa
// reconnexion — rien n'est mis en file, parce que la base est déjà la file.
func PousserRelais(db *sql.DB, proprietaire string) (bool, error) {
	candidates := sessionmgr.Sessions.SessionsMachine(proprietaire, sessionmgr.FraicheurTunnel())
	if len(candidates) == 0 {
		return false, nil
	}
	demande, etat, err := clusterdatabase.RelaisDemandes(db, proprietaire)
	if err != nil {
		return false, err
	}
	mode := ModeRelaisCore
	if !etat.Pilote {
		mode = ModeRelaisFichier
	}

	var derniere error
	for _, sess := range candidates {
		msg := composerLa0419("serveur_central", sess.SessionID, mode, etat.Revision, demande)
		if err := sendmessage.SendMessage(msg, sess.ClientSoftwareID, sess.DuckySession); err != nil {
			derniere = err
			continue
		}
		logs.Write_Log("INFO", fmt.Sprintf("relais : révision %d poussée à %s (mode %s)", etat.Revision, proprietaire, mode))
		return true, nil
	}
	return false, fmt.Errorf("%d session(s) du tunnel essayée(s), aucun envoi n'a abouti : %v", len(candidates), derniere)
}
