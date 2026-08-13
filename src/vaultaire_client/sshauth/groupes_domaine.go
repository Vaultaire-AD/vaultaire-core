package sshauth

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	localusermanagement "vaultaire_client/tools/local_user_management"
)

// Synchronisation des groupes du domaine, côté agent.
//
//	03_08  demande   (agent → core)   contenu vide
//	  03_09  liste   (core → agent)   sync:<minutes> puis <nom>:<id_group>
//	  03_10  refus   (core → agent)   <raison>
//
// L'agent émet au démarrage du service, puis à la cadence que le core lui
// annonce, et une fois de plus quand une ouverture de session révèle un groupe
// annoncé mais absent localement — le seul moment où l'écart est visible et où
// il a une conséquence immédiate.

// PrefixeCadence ouvre la ligne de cadence dans la réponse 03_09.
//
// Déclarée des deux côtés, comme PrefixeGroupes, et figée par des tests jumeaux :
// l'agent et le core sont des modules Go distincts, rien ne peut les tenir liées
// à la compilation. Une divergence ferait lire la ligne de cadence comme un
// groupe nommé « sync » — écarté par la validation, donc sans dégât, mais la
// cadence resterait celle du repli sans que rien ne le dise. D'où le test.
const PrefixeCadence = "sync:"

// CadenceParDefaut s'applique tant que le core n'a rien annoncé.
//
// Une valeur de REPLI, pas un réglage : la vraie valeur vit dans la base du core
// (`group_sync_minutes`) et voyage dans 03_09. Elle sert au tout premier cycle,
// avant la première réponse, et après un refus.
const CadenceParDefaut = 60 * time.Minute

var (
	cadenceMu sync.RWMutex
	cadence   = CadenceParDefaut

	// declencher réveille la boucle hors de son tour. Tamponnée à 1 : deux
	// sessions qui découvrent le même groupe manquant à une seconde d'intervalle
	// ne doivent pas produire deux synchronisations.
	declencher = make(chan struct{}, 1)
)

// Cadence rend la période courante.
func Cadence() time.Duration {
	cadenceMu.RLock()
	defer cadenceMu.RUnlock()
	return cadence
}

// DemanderSynchro réveille la boucle sans attendre son tour.
//
// Ne bloque jamais : si un réveil est déjà en attente, celui-ci est abandonné —
// la synchronisation qui va partir couvrira le même besoin.
func DemanderSynchro() {
	select {
	case declencher <- struct{}{}:
	default:
	}
}

// HandleGroupSync traite une réponse 03_09.
//
// Le contenu est « sync:<minutes> » puis une ligne par groupe. La ligne de
// cadence est reconnue à son PRÉFIXE et non à son rang, pour la même raison que
// celle des groupes dans 03_02 : un core qui ne l'enverrait pas ne doit pas faire
// lire le premier groupe comme une cadence.
func HandleGroupSync(content string) {
	lignes := strings.Split(strings.TrimSpace(content), "\n")

	var annonces []localusermanagement.GroupeDomaine
	var rejetees int

	for _, l := range lignes {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, PrefixeCadence) {
			appliquerCadence(strings.TrimPrefix(l, PrefixeCadence))
			continue
		}
		g, err := localusermanagement.AnalyserLigneGroupe(l)
		if err != nil {
			// Une ligne rejetée n'emporte pas les autres. Mais elle est dite en
			// WARNING : elle signifie que le core a annoncé quelque chose que
			// l'agent refuse d'écrire dans /etc/group, ce qui n'est jamais banal.
			logs.Write_log("WARNING", fmt.Sprintf(
				"groupes du domaine : ligne rejetée : %v", err))
			rejetees++
			continue
		}
		annonces = append(annonces, g)
	}

	// UNE LISTE VIDE N'EST PAS UNE LISTE ABSENTE, et la distinction compte.
	//
	// Un domaine peut légitimement n'avoir aucun groupe, et il faut alors vider
	// ceux qui restent. Mais une réponse dont TOUTES les lignes ont été rejetées
	// ressemble à une liste vide, et vider le parc sur la foi d'une trame
	// illisible serait exactement le mauvais réflexe.
	if len(annonces) == 0 && rejetees > 0 {
		logs.Write_log("ERROR", fmt.Sprintf(
			"groupes du domaine : %d ligne(s) rejetée(s) et aucune valide — "+
				"synchronisation abandonnée, les groupes locaux sont conservés", rejetees))
		return
	}

	res, err := localusermanagement.SynchroniserGroupesDomaine(annonces)
	if err != nil {
		logs.Write_log("ERROR", "groupes du domaine : synchronisation échouée : "+err.Error())
		return
	}

	logs.Write_log("INFO", fmt.Sprintf(
		"groupes du domaine : %d annoncé(s), %d créé(s), %d vidé(s), %d ignoré(s)",
		len(annonces), len(res.Crees), len(res.Vides), len(res.Ignores)))
}

// HandleGroupSyncRefus traite une 03_10.
//
// Rien n'est touché : les groupes locaux restent tels quels. Un core qui ne peut
// pas répondre n'est pas un core qui annonce une liste vide, et les confondre
// viderait le parc à la première base indisponible.
func HandleGroupSyncRefus(content string) {
	motif := strings.TrimSpace(strings.SplitN(content, "\n", 2)[0])
	if motif == "" {
		motif = "sans motif"
	}
	logs.Write_log("WARNING",
		"groupes du domaine : le core a refusé la synchronisation ("+motif+
			") — les groupes locaux sont conservés")
}

// appliquerCadence lit la période annoncée par le core.
func appliquerCadence(texte string) {
	minutes, err := strconv.Atoi(strings.TrimSpace(texte))
	if err != nil || minutes <= 0 {
		logs.Write_log("WARNING", fmt.Sprintf(
			"groupes du domaine : cadence %q illisible, repli sur %s", texte, CadenceParDefaut))
		return
	}

	nouvelle := time.Duration(minutes) * time.Minute
	cadenceMu.Lock()
	ancienne := cadence
	cadence = nouvelle
	cadenceMu.Unlock()

	if ancienne != nouvelle {
		logs.Write_log("INFO", fmt.Sprintf(
			"groupes du domaine : cadence de synchronisation portée à %s", nouvelle))
	}
}
