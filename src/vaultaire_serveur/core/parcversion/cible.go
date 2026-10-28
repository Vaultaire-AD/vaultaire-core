package parcversion

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// La version ATTENDUE d'un agent — TO-DO 111.
//
// # Trois niveaux, une règle de résolution
//
//	machine  id_logiciels.agent_target_version   dérogation : le poste qu'on fige
//	groupe   groups.agent_target_version         le niveau ordinaire : les anneaux
//	parc     server_settings.agent_target_version  le défaut
//
// Machine, sinon LA PLUS HAUTE des cibles de ses groupes, sinon le défaut du
// parc, sinon RIEN.
//
// « La plus haute » entre groupes : une machine du groupe pilote et du groupe
// général doit recevoir la version du pilote, qui est en avance — c'est tout
// l'intérêt d'un anneau. Le cas inverse, la machine qu'on veut laisser derrière,
// est celui de la dérogation par machine.
//
// # Rien = aucune mise à jour automatique, et c'est le défaut
//
// Une installation en service ne doit rien voir changer tant que personne n'a
// posé de cible. C'est la seule façon d'introduire un mécanisme qui remplace
// des binaires sans surprendre un parc qui tourne.
//
// # Une valeur illisible ne se contourne pas
//
// Les écritures passent par NormaliserCible : une valeur illisible en base n'a
// pu y entrer qu'à la main, ou par une version future. Elle est traitée
// prudemment, selon le niveau :
//
//   - une DÉROGATION illisible donne « aucune cible ». Retomber sur la cible du
//     groupe ferait exactement ce que la dérogation était là pour empêcher :
//     mettre à jour le poste qu'on voulait figer ;
//   - la cible illisible d'un GROUPE est écartée, les autres groupes comptent.
//     Elle n'empêche rien qu'une autre cible lisible n'ait décidé ;
//   - un DÉFAUT DU PARC illisible donne « aucune cible ».
//
// Dans tous les cas la valeur est rendue (Illisible), pour que la vue la montre :
// un réglage qu'on croit posé et qui ne compte pas doit se voir.

// CleReglageParc est la clé du défaut du parc dans server_settings.
const CleReglageParc = "agent_target_version"

// AucuneCible est le mot qui efface une cible, en ligne de commande comme dans
// un formulaire. « --none » est accepté aussi, pour la ligne de commande.
const AucuneCible = "none"

// formeCible : trois entiers, un « v » initial toléré, rien d'autre.
//
// Plus strict que Lire, et c'est voulu. Lire lit ce qu'une machine DÉCLARE et
// en garde le triplet de tête ; une cible est une CONSIGNE. « 2.3.1-rc1 » lu
// comme 2.3.1 désignerait une version postérieure à la pré-version qu'on a
// voulu nommer, et « 2.3 » pourrait être 2.3.0 ou une saisie tronquée.
var formeCible = regexp.MustCompile(`^v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)

// EstEffacement dit si la saisie demande de retirer la cible.
func EstEffacement(saisie string) bool {
	s := strings.ToLower(strings.TrimSpace(saisie))
	return s == AucuneCible || s == "--"+AucuneCible
}

// NormaliserCible valide une version saisie et rend sa forme rangée en base.
//
// « v2.3.1 » devient « 2.3.1 » : deux écritures de la même cible ne doivent
// pas apparaître comme deux cibles dans la vue.
func NormaliserCible(saisie string) (string, error) {
	s := strings.TrimSpace(saisie)
	if !formeCible.MatchString(s) {
		return "", fmt.Errorf("version %q refusée : trois nombres attendus, par "+
			"exemple 2.3.1 (ni pré-version, ni métadonnée de build)", saisie)
	}
	v, ok := Lire(s)
	if !ok {
		return "", fmt.Errorf("version %q illisible", saisie)
	}
	return v.String(), nil
}

// Source dit d'où vient la version attendue d'une machine.
type Source string

const (
	SourceAucune  Source = ""
	SourceMachine Source = "machine"
	SourceGroupe  Source = "groupe"
	SourceParc    Source = "parc"
)

// Cibles réunit ce que la base porte pour UNE machine.
type Cibles struct {
	// Derogation : id_logiciels.agent_target_version, brute.
	Derogation string
	// Groupes : nom du groupe → groups.agent_target_version, brute. Les groupes
	// sans cible peuvent y figurer avec une valeur vide.
	Groupes map[string]string
	// Parc : server_settings.agent_target_version, brute.
	Parc string
}

// Attendue est le résultat de la résolution.
type Attendue struct {
	// Definie est faux quand aucune cible ne s'applique — aucune mise à jour.
	Definie bool
	Version Version
	Source  Source
	// Groupe nomme le groupe qui a décidé, quand Source vaut SourceGroupe.
	Groupe string
	// Illisible porte une valeur trouvée en base et non retenue.
	Illisible string
}

// Lisible rend « 2.3.1 (groupe pilote) », « — » sans cible.
func (a Attendue) Lisible() string {
	if !a.Definie {
		if a.Illisible != "" {
			return "— (illisible : " + a.Illisible + ")"
		}
		return "—"
	}
	switch a.Source {
	case SourceMachine:
		return a.Version.String() + " (dérogation)"
	case SourceGroupe:
		return a.Version.String() + " (groupe " + a.Groupe + ")"
	case SourceParc:
		return a.Version.String() + " (parc)"
	}
	return a.Version.String()
}

// Resoudre applique la règle : machine, sinon la plus haute des cibles de
// groupe, sinon le parc, sinon rien.
func Resoudre(c Cibles) Attendue {
	if d := strings.TrimSpace(c.Derogation); d != "" {
		v, ok := lireCible(d)
		if !ok {
			return Attendue{Source: SourceMachine, Illisible: d}
		}
		return Attendue{Definie: true, Version: v, Source: SourceMachine}
	}

	// Les noms triés : à versions égales, le groupe nommé est toujours le
	// même, et la vue ne change pas d'un appel à l'autre.
	noms := make([]string, 0, len(c.Groupes))
	for nom := range c.Groupes {
		noms = append(noms, nom)
	}
	sort.Strings(noms)

	var meilleure Attendue
	illisible := ""
	for _, nom := range noms {
		brute := strings.TrimSpace(c.Groupes[nom])
		if brute == "" {
			continue
		}
		v, ok := lireCible(brute)
		if !ok {
			if illisible == "" {
				illisible = brute
			}
			continue
		}
		if !meilleure.Definie || meilleure.Version.Avant(v) {
			meilleure = Attendue{Definie: true, Version: v, Source: SourceGroupe, Groupe: nom}
		}
	}
	if meilleure.Definie {
		return meilleure
	}

	if p := strings.TrimSpace(c.Parc); p != "" {
		v, ok := lireCible(p)
		if !ok {
			return Attendue{Source: SourceParc, Illisible: p}
		}
		return Attendue{Definie: true, Version: v, Source: SourceParc}
	}
	return Attendue{Illisible: illisible}
}

// lireCible lit une cible rangée en base, avec la même exigence qu'à
// l'écriture.
func lireCible(brute string) (Version, bool) {
	n, err := NormaliserCible(brute)
	if err != nil {
		return Version{}, false
	}
	return Lire(n)
}

// Etat situe une machine par rapport à sa version attendue.
type Etat string

const (
	// EtatSansCible : aucune cible ne s'applique, rien ne sera fait.
	EtatSansCible Etat = "sans cible"
	EtatAJour     Etat = "à jour"
	EtatEnRetard  Etat = "en retard"
	// EtatEnAvance : la machine déclare plus récent que sa cible. L'agent
	// refuse de rétrograder sans ordre explicite : elle restera telle quelle.
	EtatEnAvance Etat = "en avance"
	// EtatInconnue : une cible s'applique, mais la version déclarée est vide
	// ou illisible. Comptée avec celles à traiter — voir Lire.
	EtatInconnue Etat = "inconnue"
)

// Situer compare la version déclarée à l'attendue.
func Situer(declaree string, a Attendue) Etat {
	if !a.Definie {
		return EtatSansCible
	}
	v, ok := Lire(declaree)
	switch {
	case !ok:
		return EtatInconnue
	case v.Avant(a.Version):
		return EtatEnRetard
	case a.Version.Avant(v):
		return EtatEnAvance
	}
	return EtatAJour
}

// AUnEcart dit si l'état demande un regard : en retard, ou inconnue.
func (e Etat) AUnEcart() bool { return e == EtatEnRetard || e == EtatInconnue }

// OrdreDesEtats fixe l'ordre d'affichage des compteurs : ce qui demande un
// regard d'abord.
var OrdreDesEtats = []Etat{EtatEnRetard, EtatInconnue, EtatEnAvance, EtatAJour, EtatSansCible}
