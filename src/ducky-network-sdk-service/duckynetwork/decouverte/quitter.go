package decouverte

import (
	"net"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Quitter un nœud que le cluster met en maintenance — TO-DO 216.
//
// La 04_17 d'une purge (cores : 147, proxies : 176) porte, après son motif, une
// ligne « quitter <hôte:port> » par accès du nœud purgé. L'agent :
//
//  1. le place en DERNIER dans l'ordre d'essai pendant FenetreEvitement — il
//     reste joignable s'il est le seul : un nœud en maintenance accepte encore
//     les connexions (177), et un parc sans autre nœud ne doit pas se couper ;
//  2. prévient ses abonnés (SurQuitter) : l'agent quitte le nœud s'il y est
//     connecté, sans attendre une liste qui peut revenir vide.
//
// # Pourquoi la liste ne suffisait pas
//
// Recette du 25/10 : après la purge, le poste restait connecté par le proxy.
// Une liste redemandée qui revient vide est conservée telle quelle (voir
// Enregistrer) et ne fait pas basculer ; et une session fermée par la purge se
// rouvre dans l'ordre de la liste en main, où le nœud purgé est encore premier.

// FenetreEvitement : combien de temps un nœud quitté reste en queue de liste.
// Celle de la purge d'un proxy côté core (15 min) : au-delà, la maintenance est
// soit levée, soit le nœud est sorti des listes.
const FenetreEvitement = 15 * time.Minute

// PrefixeQuitter ouvre une ligne « quitter » de la 04_17 — le pendant de
// hosthandler.PrefixeQuitter côté core.
const PrefixeQuitter = "quitter "

var (
	evitesMu   sync.Mutex
	evites     = map[string]time.Time{} // accès normalisé → fin de l'évitement
	quitteurs  []func([]string)
	maintenant = time.Now
)

// SurQuitter enregistre une fonction appelée avec les accès à quitter.
func SurQuitter(f func([]string)) {
	if f == nil {
		return
	}
	evitesMu.Lock()
	quitteurs = append(quitteurs, f)
	evitesMu.Unlock()
}

// LireActualisation sépare le motif d'une 04_17 des accès à quitter.
func LireActualisation(contenu string) (motif string, quitter []string) {
	for i, ligne := range strings.Split(contenu, "\n") {
		ligne = strings.TrimSpace(ligne)
		switch {
		case i == 0:
			motif = ligne
		case strings.HasPrefix(ligne, PrefixeQuitter):
			if a := strings.TrimSpace(strings.TrimPrefix(ligne, PrefixeQuitter)); a != "" {
				quitter = append(quitter, a)
			}
		}
	}
	return motif, quitter
}

// Eviter place ces accès en queue de liste pour FenetreEvitement, et prévient
// les abonnés.
func Eviter(acces []string) {
	if len(acces) == 0 {
		return
	}
	evitesMu.Lock()
	fin := maintenant().Add(FenetreEvitement)
	for _, a := range acces {
		if n := normaliserAcces(a); n != "" {
			evites[n] = fin
		}
	}
	destinataires := append([]func([]string){}, quitteurs...)
	evitesMu.Unlock()

	logs.Write_log("INFO", "découverte : nœud à quitter, placé en dernier pendant "+
		FenetreEvitement.String()+" : "+strings.Join(acces, ", "))
	for _, f := range destinataires {
		f(acces)
	}
}

// EstEvite dit si un accès est en cours d'évitement.
func EstEvite(acces string) bool {
	n := normaliserAcces(acces)
	if n == "" {
		return false
	}
	evitesMu.Lock()
	defer evitesMu.Unlock()
	fin, ok := evites[n]
	if !ok {
		return false
	}
	if !maintenant().Before(fin) {
		delete(evites, n)
		return false
	}
	return true
}

// MemeAcces compare deux « hôte:port », crochets IPv6 et casse compris.
func MemeAcces(a, b string) bool {
	na, nb := normaliserAcces(a), normaliserAcces(b)
	return na != "" && na == nb
}

func normaliserAcces(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return ""
	}
	if h, p, err := net.SplitHostPort(a); err == nil {
		return strings.ToLower(strings.Trim(h, "[]")) + "|" + p
	}
	// « fd00::2:6666 » sans crochets : ce que rend Noeud.Adresse pour une IPv6.
	if i := strings.LastIndex(a, ":"); i > 0 {
		return strings.ToLower(strings.Trim(a[:i], "[]")) + "|" + a[i+1:]
	}
	return strings.ToLower(a)
}

// enQueue déplace les accès évités à la fin, sans changer l'ordre des autres.
func enQueue(adresses []string) []string {
	var tete, queue []string
	for _, a := range adresses {
		if EstEvite(a) {
			queue = append(queue, a)
			continue
		}
		tete = append(tete, a)
	}
	return append(tete, queue...)
}
