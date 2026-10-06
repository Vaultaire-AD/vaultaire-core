// Package enligne suit la cadence à laquelle le core vérifie que ce client est
// en ligne, et règle sur elle le délai après lequel un tunnel muet est fermé
// (TO-DO 110).
//
// # Le défaut
//
// Ce client ferme lui-même un tunnel resté dix minutes sans trafic : c'est ce
// qui lui fait quitter un core qui ne répond plus, pour en joindre un autre.
// Dix minutes étaient écrites en dur.
//
// Or, entre deux cycles de GPO — une heure par défaut —, le SEUL trafic d'un
// tunnel est le 02_11 que le core envoie à sa cadence de vérification en
// ligne. Cette cadence se règle côté core, de une à soixante minutes. À dix
// minutes ou plus, chaque client fermait donc son tunnel entre deux
// battements, puis se reconnectait : tout le parc, en boucle, pour un réglage
// que rien n'interdisait.
//
// # La correction
//
// Le core annonce sa cadence en queue de chaque 02_11, derrière le préfixe
// « online: ». Le délai de fermeture devient deux cadences plus une minute,
// dix minutes au moins — la même tolérance que celle du core, avec le même
// plancher qu'avant : à la cadence par défaut, rien ne change.
//
// Même recette que « refresh: » pour les GPO et « disco: » pour la découverte :
// une ligne en queue, reconnue à son préfixe, ignorée par qui ne la connaît
// pas. Et, comme elles, non persistée : le premier 02_11 arrive dans la
// seconde qui suit l'authentification.
package enligne

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
)

// Prefixe ouvre la ligne de cadence dans la 02_11. Écrit aussi côté core
// (reglages.PrefixeCadenceEnLigne).
const Prefixe = "online:"

// PrefixeCapacites ouvre la ligne où le core dit ce qu'il sait faire, en queue
// de la même 02_11 : « capacites:relais,… ». Écrit aussi côté core
// (trame.PrefixeCapacites).
//
// # Pourquoi le core doit le dire (TO-DO 141)
//
// Le core FERME la connexion d'un client qui émet une trame que son type n'a
// pas le droit d'émettre — et, pour un core d'une version antérieure, une
// trame qu'il ne connaît pas encore est exactement cela. Un proxy mis à jour
// avant son core se ferait donc couper à chaque trame nouvelle, en boucle.
// Une trame ajoutée au protocole n'est émise que vers un core qui l'annonce.
//
// Dans la 02_11 et non dans l'accusé d'enregistrement : le 02_11 arrive à
// CHAQUE connexion, avant toute autre trame. Un client qui bascule sur un
// autre core du cluster, resté en arrière, l'apprend avant d'avoir rien émis.
const PrefixeCapacites = "capacites:"

// CapaciteRelais : ce core sait piloter les relais d'un proxy (04_18, 04_19).
const CapaciteRelais = "relais"

// Bornes de la cadence acceptée, en minutes : celles du réglage
// `check_online_minutes` côté core.
//
// Un core ne devrait jamais annoncer hors de ces bornes. Elles sont là parce
// qu'une valeur reçue du réseau qui décide de la fermeture d'un tunnel mérite
// une borne locale : une cadence d'un an ferait qu'un tunnel mort ne serait
// jamais quitté.
const (
	CadenceMinimum = 1
	CadenceMaximum = 60
)

// PlancherDelaiDeFermeture est le délai aux cadences courtes, et celui d'un
// client qui n'a reçu aucune annonce : la valeur fixe d'avant le TO-DO 110.
const PlancherDelaiDeFermeture = 10 * time.Minute

var (
	mu      sync.Mutex
	cadence time.Duration // zéro : aucune annonce reçue

	// capacites est ce que le core de la connexion COURANTE a annoncé.
	// Remplacé à chaque 02_11, jamais cumulé : ce qu'un core précédent savait
	// faire ne dit rien de celui-ci.
	capacites map[string]bool
)

// DelaiDeFermeturePour rend le silence au-delà duquel un tunnel est fermé,
// pour une cadence donnée.
//
// Deux cadences plus une minute : un battement perdu ne suffit pas, deux de
// suite disent que le core n'est plus là. La minute couvre le pas d'une
// minute du nettoyage, qui ne regarde pas plus souvent.
func DelaiDeFermeturePour(c time.Duration) time.Duration {
	d := 2*c + time.Minute
	if d < PlancherDelaiDeFermeture {
		return PlancherDelaiDeFermeture
	}
	return d
}

// Lire extrait la cadence d'un contenu de 02_11. Rend faux si la ligne est
// absente — core antérieur à la 2.2 — ou illisible.
func Lire(contenu string) (time.Duration, bool) {
	for _, ligne := range strings.Split(contenu, "\n") {
		ligne = strings.TrimSpace(ligne)
		if !strings.HasPrefix(ligne, Prefixe) {
			continue
		}
		minutes, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(ligne, Prefixe)))
		if err != nil {
			logs.Write_log("WARNING", fmt.Sprintf("vérification en ligne : cadence illisible (%q), ignorée", ligne))
			return 0, false
		}
		if minutes < CadenceMinimum || minutes > CadenceMaximum {
			logs.Write_log("WARNING", fmt.Sprintf(
				"vérification en ligne : cadence annoncée de %d min hors de %d–%d, ignorée",
				minutes, CadenceMinimum, CadenceMaximum))
			return 0, false
		}
		return time.Duration(minutes) * time.Minute, true
	}
	return 0, false
}

// Apprendre lit la cadence annoncée dans une 02_11 et règle le délai de
// fermeture des tunnels. Sans annonce, ne touche à rien.
//
// Appelée à chaque battement : n'écrit dans le journal que sur un CHANGEMENT.
func Apprendre(contenu string) {
	apprendreCapacites(contenu)

	c, ok := Lire(contenu)
	if !ok {
		return
	}
	mu.Lock()
	inchangee := c == cadence
	cadence = c
	mu.Unlock()
	if inchangee {
		return
	}
	delai := DelaiDeFermeturePour(c)
	stosession.SessionsUser.DefinirDelai(delai)
	logs.Write_log("INFO", fmt.Sprintf(
		"vérification en ligne : le core bat toutes les %s — un tunnel muet est fermé après %s", c, delai))
}

// Cadence rend la dernière cadence annoncée par le core, ou zéro si aucune ne
// l'a été.
func Cadence() time.Duration {
	mu.Lock()
	defer mu.Unlock()
	return cadence
}

// DelaiDeFermeture rend le délai en vigueur : celui de la cadence annoncée,
// ou le plancher tant qu'aucune ne l'a été. Un proxy s'en sert pour ne pas
// couper un tunnel relayé avant que ses deux bouts ne le fassent.
func DelaiDeFermeture() time.Duration {
	if c := Cadence(); c > 0 {
		return DelaiDeFermeturePour(c)
	}
	return PlancherDelaiDeFermeture
}

// LireCapacites extrait les capacités annoncées dans une 02_11. Une trame sans
// la ligne — core antérieur à la 2.2 — rend un ensemble vide.
func LireCapacites(contenu string) map[string]bool {
	out := map[string]bool{}
	for _, ligne := range strings.Split(contenu, "\n") {
		ligne = strings.TrimSpace(ligne)
		if !strings.HasPrefix(ligne, PrefixeCapacites) {
			continue
		}
		for _, c := range strings.Split(strings.TrimPrefix(ligne, PrefixeCapacites), ",") {
			if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
				out[c] = true
			}
		}
	}
	return out
}

func apprendreCapacites(contenu string) {
	lues := LireCapacites(contenu)
	mu.Lock()
	avant := capacites
	capacites = lues
	mu.Unlock()

	// Une ligne par CHANGEMENT, dans un sens comme dans l'autre : perdre une
	// capacité veut dire qu'on vient de basculer sur un core plus ancien, et
	// c'est ce qu'on cherchera dans le journal.
	for c := range lues {
		if !avant[c] {
			logs.Write_log("INFO", "core : capacité annoncée — "+c)
		}
	}
	for c := range avant {
		if !lues[c] {
			logs.Write_log("WARNING", "core : capacité « "+c+" » non annoncée par le core de cette connexion — "+
				"il est d'une version antérieure, les trames correspondantes ne lui sont plus émises")
		}
	}
}

// CoreSait dit si le core de la connexion courante a annoncé une capacité.
// Faux tant qu'aucune 02_11 n'est arrivée.
func CoreSait(capacite string) bool {
	mu.Lock()
	defer mu.Unlock()
	return capacites[strings.ToLower(capacite)]
}

// oublier remet l'état initial. Pour les tests.
func oublier() {
	mu.Lock()
	cadence = 0
	capacites = nil
	mu.Unlock()
	stosession.SessionsUser.DefinirDelai(PlancherDelaiDeFermeture)
}
