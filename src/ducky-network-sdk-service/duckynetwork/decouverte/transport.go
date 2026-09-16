package decouverte

import (
	"fmt"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
)

// Transport de la découverte : émission de 04_03, réception de 04_04.
//
// # Pourquoi l'émetteur est injecté
//
// Le reste du paquet ne dépend d'aucune couche réseau : il analyse des chaînes
// et tient une liste. C'est ce qui le rend éprouvable sans tunnel, et il vaut
// mieux que cela le reste — la logique de fusion et de tri est exactement ce
// qu'on veut pouvoir vérifier.
//
// Le même partage que `gpo.Configure` et `revocation.Configure` côté agent.

// Sender émet une trame déjà composée.
type Sender func(trame string)

var (
	envoyer     Sender
	clientID    string
	demandeInit = make(chan struct{}, 1)
)

// Configure branche l'émetteur et l'identifiant de ce client.
func Configure(s Sender, id string) {
	envoyer = s
	clientID = id
}

// CadenceParDefaut espace deux demandes de liste.
//
// # Pourquoi une constante ici, et non un réglage
//
// La cadence de synchronisation des groupes voyage dans sa trame, parce qu'elle
// pilote une action sur le système — créer et vider des groupes — dont le coût
// et le risque se règlent depuis le core.
//
// Celle-ci ne pilote qu'une lecture, dont le seul effet est de rafraîchir une
// liste d'adresses en mémoire. Lui donner un réglage ajouterait une entrée au
// catalogue, une colonne à l'interface et une question de plus à qui l'exploite,
// pour un choix que personne n'a de raison de changer.
//
// Elle est longue à dessein : la liste ne change qu'à l'ajout ou au retrait d'un
// nœud, ce qui n'arrive pas tous les jours. Une machine qui a besoin de la liste
// TOUT DE SUITE — parce que son serveur habituel ne répond plus — ne l'attend
// pas : elle bascule sur l'adresse suivante, qu'elle a déjà.
const CadenceParDefaut = 30 * time.Minute

// Demarrer arme la boucle de découverte et rend la main immédiatement.
//
// `sessionKey` est un FOURNISSEUR et non une valeur : la clé change à chaque
// rétablissement du tunnel, et une valeur capturée au démarrage serait périmée
// dès la première coupure.
func Demarrer(sessionKey func() string) {
	go boucle(sessionKey)
	logs.Write_log("INFO", fmt.Sprintf(
		"découverte : active (cadence %s, %d empreinte(s) de confiance)",
		CadenceParDefaut, EmpreintesConnues()))
}

// DemanderMaintenant réveille la boucle hors de son tour.
//
// Ne bloque jamais : si une demande est déjà en attente, celle-ci est
// abandonnée — celle qui va partir couvre le même besoin.
func DemanderMaintenant() {
	select {
	case demandeInit <- struct{}{}:
	default:
	}
}

func boucle(sessionKey func() string) {
	defer logs.Recover("découverte")

	// Premier passage immédiat : la machine doit connaître ses nœuds dès le
	// démarrage. Sans cela, un poste redémarré passerait toute la première
	// période sur sa seule liste statique — c'est-à-dire sur celle qu'on cherche
	// justement à ne plus avoir à maintenir.
	emettre(sessionKey)

	for {
		select {
		case <-time.After(CadenceParDefaut):
		case <-demandeInit:
		}
		emettre(sessionKey)
	}
}

func emettre(sessionKey func() string) {
	if envoyer == nil {
		logs.Write_log("WARNING", "découverte : aucun émetteur branché, demande abandonnée")
		return
	}
	cle := sessionKey()
	if strings.TrimSpace(cle) == "" {
		logs.Write_log("WARNING", "découverte : aucune session établie, demande abandonnée")
		return
	}
	envoyer(ConstruireDemande(cle, clientID))
}

// HandleTrame traite une trame 04_xx reçue par un CLIENT.
//
// Seules 04_04 et 04_02 y arrivent en pratique : les autres 04_xx sont des
// requêtes, que le core reçoit et non l'inverse.
func HandleTrame(t storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		return ""
	}

	switch t.Message_Order[1] {
	case "04":
		traiterListe(t.Content)
	case "02":
		logs.Write_log("INFO", "découverte : enregistrement du nœud confirmé par le core")
	case "06", "08":
		// Accusés de métriques et de battement. Rien à faire, mais nommés :
		// les laisser tomber dans le `default` les ferait passer pour des
		// trames non gérées dans le journal, et on chercherait un défaut.
	default:
		logs.Write_log("DEBUG", "découverte : sous-trame 04_"+t.Message_Order[1]+" non gérée")
	}
	return ""
}

// traiterListe applique une 04_04.
//
// # L'ordre des deux gestes
//
// Les empreintes sont apprises AVANT que la liste ne soit retenue. L'inverse
// laisserait une fenêtre — courte, mais réelle — pendant laquelle l'agent aurait
// des adresses à joindre sans de quoi reconnaître ce qui y répond. Une
// reconnexion tombant dans cette fenêtre refuserait un nœud légitime, et le
// journal parlerait de clé inattendue là où il n'y a qu'un ordre d'opérations.
func traiterListe(contenu string) {
	noeuds, err := AnalyserListe(contenu)
	if err != nil {
		logs.Write_log("WARNING", "découverte : "+err.Error())
		return
	}

	ApprendreEmpreintes(noeuds)
	Enregistrer(noeuds)

	logs.Write_log("INFO", fmt.Sprintf(
		"découverte : %d nœud(s) joignable(s) — %s", len(noeuds), Resume()))
}
