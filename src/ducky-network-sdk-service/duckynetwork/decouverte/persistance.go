package decouverte

import (
	"fmt"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/serveurauth"
)

// Persistance de la liste apprise (TO-DO 61).
//
// Le paquet ne sait pas OÙ écrire : c'est le programme qui connaît son fichier
// de configuration (l'agent le sien, en JSON ; un service le sien). Il
// s'abonne donc avec SurNouvelleListe, et reçoit chaque liste retenue.
//
// # Seuls les nœuds de CONFIANCE sont transmis
//
// Un nœud dont l'empreinte n'est pas dans la liste de confiance de la machine
// (core_key_fingerprint) n'est pas transmis. L'écrire dans un fichier en ferait
// une adresse que l'agent essaierait à chaque redémarrage — et sur une machine
// en confiance au premier usage, la première clé qu'il y rencontrerait serait
// acceptée. En mémoire, pour la durée d'une session déjà vérifiée, le risque
// est borné ; sur disque, il ne l'est plus.

var (
	abonneMu      sync.Mutex
	surNouvelle   func([]Noeud)
	derniereListe time.Time
)

// SurNouvelleListe enregistre la fonction appelée après chaque 04_04 retenue,
// avec les seuls nœuds de confiance, dans l'ordre servi par le core.
func SurNouvelleListe(f func([]Noeud)) {
	abonneMu.Lock()
	surNouvelle = f
	abonneMu.Unlock()
}

// DerniereReception rend l'heure de la dernière 04_04 analysée (zéro sinon).
func DerniereReception() time.Time {
	abonneMu.Lock()
	defer abonneMu.Unlock()
	return derniereListe
}

// empreintesDeConfiance est une variable pour les tests.
var empreintesDeConfiance = serveurauth.EmpreintesAttendues

// NoeudsDeConfiance filtre les nœuds dont l'empreinte est connue de la machine.
//
// Un PROXY est gardé dès qu'au moins un core de la liste est de confiance : il
// ne présente pas sa clé, il relaie celle d'un core, que l'agent vérifie au
// bout du tunnel. Son empreinte à lui n'est jamais apprise (voir
// ApprendreEmpreintes), elle ne peut donc pas servir de critère.
func NoeudsDeConfiance(noeuds []Noeud) []Noeud {
	liste, err := empreintesDeConfiance()
	if err != nil || len(liste) == 0 {
		return nil
	}
	connues := make(map[string]bool, len(liste))
	for _, e := range liste {
		connues[e] = true
	}
	coreDeConfiance := false
	for _, n := range noeuds {
		if n.Role != "proxy" && connues[n.Empreinte] {
			coreDeConfiance = true
			break
		}
	}
	var out []Noeud
	for _, n := range noeuds {
		if n.Role == "proxy" {
			if coreDeConfiance {
				out = append(out, n)
			}
			continue
		}
		if connues[n.Empreinte] {
			out = append(out, n)
		}
	}
	return out
}

// notifier transmet la liste à l'abonné, s'il y en a un.
func notifier(noeuds []Noeud) {
	abonneMu.Lock()
	derniereListe = time.Now()
	f := surNouvelle
	abonneMu.Unlock()
	if f == nil || len(noeuds) == 0 {
		return
	}
	fiables := NoeudsDeConfiance(noeuds)
	if len(fiables) == 0 {
		logs.Write_log("WARNING", fmt.Sprintf(
			"découverte : aucun des %d nœud(s) annoncé(s) n'a d'empreinte de confiance — liste non persistée", len(noeuds)))
		return
	}
	if len(fiables) < len(noeuds) {
		logs.Write_log("INFO", fmt.Sprintf(
			"découverte : %d nœud(s) sur %d persisté(s), les autres n'ont pas d'empreinte de confiance",
			len(fiables), len(noeuds)))
	}
	f(fiables)
}
