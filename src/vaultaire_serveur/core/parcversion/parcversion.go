// Package parcversion lit les versions que les machines du parc déclarent, et
// les compare à un minimum (TO-DO 161 ; le 111 en est l'autre lecteur prévu).
//
// # Ce que le core fait d'une version, et ce qu'il n'en fait pas
//
// La règle posée avec l'inventaire des versions (point 39) était : le core
// AFFICHE la version, il ne l'interprète jamais — aucun refus, aucun seuil.
// Une règle de comparaison se trompe sur les cas limites, et se tromper voulait
// dire fermer la porte à un parc dont le seul outil de réparation est celui
// qu'on vient de fermer.
//
// Ce paquet est la première comparaison, et il garde l'esprit de la règle :
// rien ici ne REFUSE ni ne COUPE une machine. Il répond à « combien de machines
// ne suivraient pas ce réglage », pour PRÉVENIR l'exploitant avant qu'il ne le
// pose. Le pire effet d'une erreur de lecture est donc un avertissement de trop,
// ou de moins — jamais une machine fermée dehors.
//
// # Ce qui est lu
//
// La colonne `agent_version` d'id_logiciels, remontée par la 02_12 :
//
//	2.3.0+g1939a3b (2026-08-14)
//	2.2.0 (build local)
//	(vide : jamais déclarée)
//
// Seul le triplet de tête compte. Ce qui suit « + » est une métadonnée de build,
// qui n'entre dans aucune comparaison (SemVer) — c'était déjà le statut donné au
// commit dans version.Info.Complete.
//
// `sdk_version` n'est PAS lue : la constante du SDK est restée « 2.1.0 » après
// la 2.2, alors que c'est bien un agent 2.2 qui suit la cadence annoncée. La
// version du programme est la seule qui dise ce qu'il fait.
//
// # Une version illisible n'est pas une version récente
//
// Vide, « dev », n'importe quoi : la machine est rangée « inconnue », et
// comptée avec celles qui ne suivent pas. Le doute se lève en la mettant à jour,
// pas en la supposant à jour.
package parcversion

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Version est un triplet sémantique.
type Version struct {
	Majeure, Mineure, Correctif int
}

// V construit une version, pour les seuils écrits dans le code.
func V(majeure, mineure, correctif int) Version {
	return Version{Majeure: majeure, Mineure: mineure, Correctif: correctif}
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Majeure, v.Mineure, v.Correctif)
}

// Avant dit si v précède o.
func (v Version) Avant(o Version) bool {
	if v.Majeure != o.Majeure {
		return v.Majeure < o.Majeure
	}
	if v.Mineure != o.Mineure {
		return v.Mineure < o.Mineure
	}
	return v.Correctif < o.Correctif
}

// Lire extrait le triplet de tête d'une version déclarée.
//
// Accepte un « v » initial — certains outils l'écrivent, et le refuser rangerait
// « inconnue » une machine parfaitement identifiable. Refuse tout ce qui n'est
// pas exactement trois entiers : « 2.2 » pourrait être 2.2.0 ou une saisie
// tronquée, et deviner est ce que ce paquet s'interdit.
func Lire(declaree string) (Version, bool) {
	s := strings.TrimSpace(declaree)
	s = strings.TrimPrefix(s, "v")
	// Le triplet s'arrête au premier caractère qui n'en fait pas partie :
	// « + » (métadonnée de build), espace (date, « build local »), « - »
	// (pré-version).
	if i := strings.IndexAny(s, "+ -("); i >= 0 {
		s = s[:i]
	}
	parties := strings.Split(s, ".")
	if len(parties) != 3 {
		return Version{}, false
	}
	var n [3]int
	for i, p := range parties {
		if p == "" || len(p) > 6 {
			return Version{}, false
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return Version{}, false
		}
		n[i] = v
	}
	return V(n[0], n[1], n[2]), true
}

// Machine est une ligne du parc, telle que la base la rend.
type Machine struct {
	ComputeurID string
	Hostname    string
	// Declaree est la valeur brute d'agent_version.
	Declaree string
}

// Nom rend ce qu'on montre d'une machine : son nom d'hôte, ou son
// identifiant quand elle n'en a pas encore déclaré.
func (m Machine) Nom() string {
	if strings.TrimSpace(m.Hostname) != "" {
		return m.Hostname
	}
	return m.ComputeurID
}

// VersionLisible rend la version telle qu'on l'affiche à côté du nom.
func (m Machine) VersionLisible() string {
	if strings.TrimSpace(m.Declaree) == "" {
		return "jamais déclarée"
	}
	if v, ok := Lire(m.Declaree); ok {
		return v.String()
	}
	return "illisible : " + m.Declaree
}

// Bilan range un parc par rapport à un minimum.
type Bilan struct {
	Minimum     Version
	Total       int
	Anterieures []Machine
	Inconnues   []Machine
}

// Recenser range chaque machine : à jour, antérieure au minimum, ou inconnue.
//
// Les listes sont triées par nom : deux appels sur le même parc rendent les
// mêmes « cinq premières », et un exploitant qui relance la commande ne voit
// pas la liste changer sans raison.
func Recenser(parc []Machine, minimum Version) Bilan {
	b := Bilan{Minimum: minimum, Total: len(parc)}
	for _, m := range parc {
		v, ok := Lire(m.Declaree)
		switch {
		case !ok:
			b.Inconnues = append(b.Inconnues, m)
		case v.Avant(minimum):
			b.Anterieures = append(b.Anterieures, m)
		}
	}
	parNom := func(l []Machine) {
		sort.SliceStable(l, func(i, j int) bool { return l[i].Nom() < l[j].Nom() })
	}
	parNom(b.Anterieures)
	parNom(b.Inconnues)
	return b
}

// ARisque rend le nombre de machines qui ne sont pas réputées à jour.
func (b Bilan) ARisque() int { return len(b.Anterieures) + len(b.Inconnues) }

// Premieres rend au plus n machines à risque, les antérieures d'abord — ce
// sont les plus sûres d'être touchées —, chacune avec sa version.
func (b Bilan) Premieres(n int) []string {
	out := make([]string, 0, n)
	for _, l := range [][]Machine{b.Anterieures, b.Inconnues} {
		for _, m := range l {
			if len(out) == n {
				return out
			}
			out = append(out, m.Nom()+" ("+m.VersionLisible()+")")
		}
	}
	return out
}

// Resume rend « 3 machine(s) : a (2.1.0), b (2.1.3), c (jamais déclarée) »,
// ou « … et 12 autre(s) » au-delà de n.
func (b Bilan) Resume(n int) string {
	noms := b.Premieres(n)
	s := fmt.Sprintf("%d machine(s) : %s", b.ARisque(), strings.Join(noms, ", "))
	if reste := b.ARisque() - len(noms); reste > 0 {
		s += fmt.Sprintf(" et %d autre(s)", reste)
	}
	return s
}
