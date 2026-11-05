package dbgpo

import (
	"sort"
	"strings"
)

// LE NOM D'UNE MACHINE — TO-DO 215.
//
// La conformité listait les machines par leur seul identifiant
// (`svmAFOFVMs2n-25-10-2026`) : pour savoir de quel poste il s'agissait, il
// fallait le retrouver ailleurs. Le nom d'hôte de l'inventaire (trame 02_12)
// vient maintenant en premier, l'identifiant en second.
//
// Comme le reste de ce paquet, tout est pur : la page et `vlt gpo status`
// appellent les mêmes fonctions, et disent donc la même chose.

// nomsParDefaut : les noms qu'un système se donne quand personne ne lui en a
// donné. Ils ne désignent aucune machine — dix postes peuvent s'appeler
// `localhost.localdomain` — et les afficher tels quels ferait croire qu'on a
// identifié le poste.
var nomsParDefaut = map[string]bool{
	"localhost":               true,
	"localhost.localdomain":   true,
	"localhost6":              true,
	"localhost6.localdomain6": true,
	"localhost.localdomain6":  true,
	"(none)":                  true,
}

// NomGenerique dit qu'un nom d'hôte ne désigne pas une machine en propre.
func NomGenerique(hostname string) bool {
	return nomsParDefaut[strings.ToLower(strings.TrimSpace(hostname))]
}

// LibelleNomInconnu et LibelleNomGenerique sont ce qu'on affiche à la place
// d'un nom absent ou générique.
const (
	LibelleNomInconnu   = "nom inconnu"
	LibelleNomGenerique = "nom par défaut"
)

// NomDeMachine rend ce qu'il faut afficher comme nom, et si c'est un vrai nom.
//
//   - un nom déclaré : lui-même, vrai ;
//   - aucun nom (pas encore d'inventaire) : « nom inconnu », faux ;
//   - un nom générique : « nom par défaut (localhost.localdomain) », faux — le
//     nom brut reste lisible, pour qu'on sache quoi corriger sur le poste
//     (`hostnamectl set-hostname`).
func NomDeMachine(hostname string) (string, bool) {
	h := strings.TrimSpace(hostname)
	switch {
	case h == "":
		return LibelleNomInconnu, false
	case NomGenerique(h):
		return LibelleNomGenerique + " (" + h + ")", false
	default:
		return h, true
	}
}

// Nom rend le nom à afficher pour une machine — voir NomDeMachine.
func (l LigneMachine) Nom() string {
	n, _ := NomDeMachine(l.Hostname)
	return n
}

// NomIdentifiant dit si la machine a un vrai nom.
func (l LigneMachine) NomIdentifiant() bool {
	_, ok := NomDeMachine(l.Hostname)
	return ok
}

// TrierParNom range les machines par nom d'hôte, sans tenir compte de la casse.
//
// Les machines sans vrai nom vont à la fin, entre elles par identifiant : les
// mêler aux autres sous « localhost… » les grouperait sous un nom qui ne veut
// rien dire. Stable : à nom égal, l'ordre de gravité d'origine est gardé.
//
// Ce n'est PAS l'ordre par défaut. La vue s'ouvre sur ce qui va mal
// (TrierMachines) ; ce tri est celui qu'on choisit pour retrouver un poste.
func TrierParNom(machines []LigneMachine) {
	sort.SliceStable(machines, func(a, b int) bool {
		na, nb := machines[a].NomIdentifiant(), machines[b].NomIdentifiant()
		if na != nb {
			return na
		}
		if !na {
			return machines[a].ComputeurID < machines[b].ComputeurID
		}
		return strings.ToLower(machines[a].Hostname) < strings.ToLower(machines[b].Hostname)
	})
}

// Correspond dit si une machine répond à une recherche : sur le nom d'hôte ou
// l'identifiant, sans casse, par sous-chaîne. Vide : tout correspond.
func (l LigneMachine) Correspond(recherche string) bool {
	r := strings.ToLower(strings.TrimSpace(recherche))
	if r == "" {
		return true
	}
	return strings.Contains(strings.ToLower(l.Hostname), r) ||
		strings.Contains(strings.ToLower(l.ComputeurID), r)
}

// MachinesNommees rend les identifiants des machines dont le nom d'hôte est
// EXACTEMENT `nom` (sans casse) — pour `vlt gpo status <nom>`. Plusieurs
// identifiants : le nom est porté par plusieurs postes, il faut choisir.
// Un nom générique ne désigne personne : rien n'est rendu.
func MachinesNommees(rows []ComplianceRow, nom string) []string {
	nom = strings.TrimSpace(nom)
	if nom == "" || NomGenerique(nom) {
		return nil
	}
	vus := map[string]bool{}
	var ids []string
	for _, r := range rows {
		if strings.EqualFold(strings.TrimSpace(r.Hostname), nom) && !vus[r.ComputeurID] {
			vus[r.ComputeurID] = true
			ids = append(ids, r.ComputeurID)
		}
	}
	sort.Strings(ids)
	return ids
}
