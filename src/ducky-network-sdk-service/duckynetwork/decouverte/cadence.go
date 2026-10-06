package decouverte

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Cadence de la demande de liste, décidée par le core.
//
// # Ce qui a changé, et pourquoi
//
// Cette cadence était une constante, avec un argument écrit ici même : « elle
// ne pilote qu'une lecture, dont le seul effet est de rafraîchir une liste
// d'adresses en mémoire ».
//
// L'argument ne tient plus depuis qu'on s'en sert pour BASCULER. Une liste
// rafraîchie ne sert plus seulement à connaître des adresses de secours : elle
// peut décider que le nœud en cours d'usage n'est plus le bon, et provoquer une
// reconnexion. Ce qu'elle pilote est donc devenu un effet sur le parc, comme la
// synchronisation des groupes et le rafraîchissement des GPO — et comme eux,
// cela se règle depuis le core.
//
// La valeur voyage en queue de 04_04, derrière PrefixeCadence.

// PrefixeCadence ouvre la ligne de cadence dans la trame 04_04.
//
// Déclaré des deux côtés — ici et dans le host_handler du core — et figé par
// des tests jumeaux : rien ne peut lier ces deux chaînes à la compilation, et
// les faire diverger ferait rejeter la ligne comme un nœud malformé.
const PrefixeCadence = "disco:"

// CadenceParDefaut espace deux demandes de liste tant que le core n'a rien dit.
//
// Elle est longue à dessein : la liste ne change qu'à l'ajout ou au retrait
// d'un nœud, ce qui n'arrive pas tous les jours. Une machine qui a besoin de la
// liste TOUT DE SUITE — parce que son serveur habituel ne répond plus — ne
// l'attend pas : elle bascule sur l'adresse suivante, qu'elle a déjà.
const CadenceParDefaut = 30 * time.Minute

// Bornes de ce qu'un core peut demander, identiques à celles du réglage
// `node_list_refresh_minutes`.
//
// Elles sont là parce qu'une valeur reçue du RÉSEAU pilote ici une boucle
// infinie : une cadence nulle transformerait l'agent en générateur de trafic,
// et une cadence d'un mois le laisserait ignorer un nœud retiré bien après que
// tout le monde l'a oublié.
const (
	CadenceMinimum = 5 * time.Minute
	CadenceMaximum = 24 * time.Hour
)

var (
	cadenceMu sync.Mutex
	cadence   = CadenceParDefaut

	// reveilCadence réarme la boucle quand la valeur change. Capacité 1 et
	// écriture non bloquante : un réveil déjà en attente rend le suivant
	// inutile.
	reveilCadence = make(chan struct{}, 1)
)

// Cadence rend l'intervalle en vigueur.
func Cadence() time.Duration {
	cadenceMu.Lock()
	defer cadenceMu.Unlock()
	return cadence
}

// appliquerCadenceDepuis lit une ligne « disco:<minutes> ».
func appliquerCadenceDepuis(ligne string) {
	brut := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ligne), PrefixeCadence))
	minutes, err := strconv.Atoi(brut)
	if err != nil {
		logs.Write_log("WARNING", "découverte : cadence illisible dans la 04_04 : "+ligne)
		return
	}
	definirCadence(time.Duration(minutes) * time.Minute)
}

// definirCadence pose la valeur, bornée, et réveille la boucle si elle change.
func definirCadence(nouvelle time.Duration) {
	switch {
	case nouvelle < CadenceMinimum:
		nouvelle = CadenceMinimum
	case nouvelle > CadenceMaximum:
		nouvelle = CadenceMaximum
	}

	cadenceMu.Lock()
	change := nouvelle != cadence
	cadence = nouvelle
	cadenceMu.Unlock()

	if !change {
		return
	}
	logs.Write_log("INFO", fmt.Sprintf(
		"découverte : cadence portée à %s par le core", nouvelle))
	// Sans ce réveil, une cadence raccourcie n'entrerait en vigueur qu'au terme
	// de l'ancienne attente — jusqu'à une demi-heure de retard sur un
	// changement fait précisément pour aller plus vite.
	signalerCadence()
}

func signalerCadence() {
	select {
	case reveilCadence <- struct{}{}:
	default:
	}
}
