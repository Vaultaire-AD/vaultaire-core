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

// Demarrer arme la boucle de découverte et rend la main immédiatement.
//
// `sessionKey` est un FOURNISSEUR et non une valeur : la clé change à chaque
// rétablissement du tunnel, et une valeur capturée au démarrage serait périmée
// dès la première coupure.
func Demarrer(sessionKey func() string) {
	go boucle(sessionKey)
	logs.Write_log("INFO", fmt.Sprintf(
		"découverte : active (cadence %s par défaut, %d empreinte(s) de confiance)",
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
		// La cadence est RELUE à chaque tour : le core peut la changer par la
		// ligne « disco: » de n'importe quelle 04_04, et une valeur capturée
		// une fois ne bougerait plus jusqu'au redémarrage de l'agent.
		select {
		case <-time.After(Cadence()):
		case <-demandeInit:
		case <-reveilCadence:
			// La cadence vient de changer : on réarme sur la nouvelle valeur
			// sans émettre. Redemander la liste ici ferait redemander tout le
			// parc à la seconde où l'on touche au réglage — exactement la
			// rafale que la cadence sert à éviter.
			continue
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
// Seules 04_04, 04_02 et, pour un proxy, 04_16 y arrivent en pratique : les autres 04_xx sont des
// requêtes, que le core reçoit et non l'inverse.
func HandleTrame(t storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		return ""
	}

	switch t.Message_Order[1] {
	case "04":
		traiterListe(t.Content)
	case "02":
		traiterAccuseEnregistrement(t.Content)
	case "16":
		traiterServices(t.Content)
	case "17":
		// « Redemande ta liste maintenant ». Elle ne transporte AUCUNE liste :
		// l'agent repart sur une 04_03 ordinaire, et tout le chemin habituel —
		// filtrage par groupes, tri, empreintes, persistance — reste identique.
		// Une trame de réveil ne pouvait pas devenir un second chemin
		// d'apprentissage, qu'il aurait fallu tenir d'accord avec le premier.
		motif := strings.TrimSpace(t.Content)
		if motif == "" {
			motif = "demande du core"
		}
		logs.Write_log("INFO", "découverte : liste redemandée hors tour ("+motif+")")
		DemanderMaintenant()
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
	// Après l'apprentissage des empreintes : un nœud dont l'empreinte vient
	// d'être retenue est persistable dès cette liste-ci.
	notifier(noeuds)

	logs.Write_log("INFO", fmt.Sprintf(
		"découverte : %d nœud(s) joignable(s) — %s", len(noeuds), Resume()))
}

// traiterAccuseEnregistrement lit le 04_02.
//
//	ok              enregistrement accepté
//	refus\n<motif>  refusé, motif en seconde ligne (point 73)
//
// Un contenu vide vaut « accepté » : les cores antérieurs au point 73 n'ont
// jamais refusé par ce canal, et leur accusé se réduisait parfois à son en-tête.
func traiterAccuseEnregistrement(contenu string) {
	lignes := strings.Split(strings.TrimSpace(contenu), "\n")
	statut := strings.ToLower(strings.TrimSpace(lignes[0]))
	if statut == "refus" || statut == "refuse" || statut == "refusé" {
		motif := "sans motif"
		if len(lignes) > 1 && strings.TrimSpace(lignes[1]) != "" {
			motif = strings.TrimSpace(lignes[1])
		}
		logs.Write_log("ERROR", "découverte : enregistrement du nœud REFUSÉ par le core — "+motif)
		SignalerAccuseEnregistrement(false, motif)
		return
	}
	logs.Write_log("INFO", "découverte : enregistrement du nœud confirmé par le core")
	SignalerAccuseEnregistrement(true, "")
}
