// Package netguard borne ce qu'une source peut consommer avant de s'être
// authentifiée.
//
// # Le problème qu'il ferme
//
// Les écoutes Ducky et LDAP acceptaient un nombre illimité de connexions
// simultanées, sans distinction d'origine. Une connexion coûte un descripteur de
// fichier, une goroutine et une entrée de registre — et rien de tout cela ne
// demande d'identifiant.
//
// Le balayage périodique nettoie les connexions inactives, mais il tourne toutes
// les deux minutes : entre deux passages, la fenêtre reste largement ouverte.
// Quelques milliers de connexions muettes suffisent à épuiser les descripteurs
// du processus, ce qui emporte LDAP, DNS, l'interface web et l'API avec Ducky.
//
// # Pourquoi par ADRESSE et pas seulement au total
//
// Un plafond global protège le serveur mais laisse une seule source affamer tout
// le parc : elle prend les places, les postes légitimes sont refusés. Le plafond
// par adresse garde la panne du côté de celui qui la provoque.
//
// Les deux sont posés : par adresse contre l'abus, au total contre la somme des
// usages normaux plus l'abus.
package netguard

import (
	"fmt"
	"net"
	"sync"
)

// Limiter compte les connexions en cours, au total et par adresse source.
type Limiter struct {
	nom           string
	maxTotal      int
	maxParAdresse int
	mu            sync.Mutex
	total         int
	parAdresse    map[string]int
}

// NewLimiter construit un limiteur.
//
// Une borne à zéro ou négative désactive le contrôle correspondant : c'est un
// choix d'exploitant, pas un défaut.
func NewLimiter(nom string, maxTotal, maxParAdresse int) *Limiter {
	return &Limiter{
		nom:           nom,
		maxTotal:      maxTotal,
		maxParAdresse: maxParAdresse,
		parAdresse:    make(map[string]int),
	}
}

// Acquire réserve une place pour une connexion.
//
// Retourne une fonction de libération et un booléen. La fonction est TOUJOURS
// non nulle, même en cas de refus : l'appelant peut la différer sans test, ce
// qui évite l'oubli le plus courant.
func (l *Limiter) Acquire(conn net.Conn) (func(), bool, string) {
	source := SourceAddr(conn)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return func() {}, false, fmt.Sprintf(
			"plafond global atteint (%d connexions %s en cours)", l.total, l.nom)
	}
	if l.maxParAdresse > 0 && l.parAdresse[source] >= l.maxParAdresse {
		return func() {}, false, fmt.Sprintf(
			"plafond par adresse atteint pour %s (%d connexions %s)",
			source, l.parAdresse[source], l.nom)
	}

	l.total++
	l.parAdresse[source]++

	var une sync.Once
	return func() {
		// sync.Once : une double libération décrémenterait deux fois et finirait
		// par rendre le compteur négatif, donc le plafond inopérant. C'est le
		// genre d'erreur qu'un defer mal placé introduit sans bruit.
		une.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.parAdresse[source] <= 1 {
				// Retirer l'entrée plutôt que la laisser à zéro : sinon la table
				// grossit d'une entrée par adresse ayant tenté une connexion,
				// ce qu'un balayage produit précisément en masse.
				delete(l.parAdresse, source)
			} else {
				l.parAdresse[source]--
			}
		})
	}, true, ""
}

// Stats rend les compteurs, pour la supervision.
func (l *Limiter) Stats() (total, sources int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.parAdresse)
}

// SourceAddr rend l'adresse du pair, sans le port.
//
// Sans ce découpage, chaque connexion aurait une clé différente — le port source
// change à chaque fois — et le plafond par adresse ne compterait jamais au-delà
// de un.
func SourceAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
