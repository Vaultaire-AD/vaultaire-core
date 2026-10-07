package dbgpo

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"vaultaire/core/gpo"
)

// Le parc, une ligne par MACHINE — TO-DO 143.
//
// # Ce qui n'allait pas
//
// La liste rendait une ligne par couple (machine, portée) : la portée machine,
// puis une ligne par personne passée sur le poste. Un poste partagé par dix
// personnes occupait onze lignes, qui ouvraient toutes la même fiche.
//
// Et le résumé, lui, comptait bien des machines — mais en jugeant chaque ligne
// comme si c'était une machine. Une portée UTILISATEUR ne rapporte qu'à la
// connexion de la personne : trois heures après son départ, sa ligne passait
// « en retard », et la machine avec elle. Un parc où tout le monde est rentré
// chez soi s'affichait en retard chaque soir.
//
// # La règle
//
//   - une ligne par machine, qui porte l'état de sa portée MACHINE ;
//   - la fraîcheur — à jour, en retard, jamais — est celle de la portée
//     machine. C'est elle qui rapporte à cadence fixe ; le silence d'un compte
//     veut seulement dire que la personne n'est pas là ;
//   - les portées utilisateur vont dans la fiche. Elles ne REMONTENT dans la
//     liste que lorsqu'il y a quelque chose à y lire : un écart, un module en
//     échec, ou une politique appliquée que personne n'a jamais vérifiée ;
//   - pour le tri, le résumé et la vue des écarts, le pire état l'emporte :
//     une machine dont un dossier personnel a dérivé n'est pas conforme parce
//     que sa portée machine l'est.
//
// Tout est pur, comme le reste de ce que ce paquet décide : des lignes en
// entrée, un instant en paramètre. La ligne de commande et le portail
// empruntent les mêmes fonctions — c'est ce qui les fait dire la même chose.

// LigneMachine est l'état d'une machine, toutes portées réunies.
type LigneMachine struct {
	ComputeurID string

	// Machine est la portée machine. Sans valeur (AMachine faux) tant que le
	// poste n'a rapporté que pour des comptes — le temps d'un premier cycle.
	Machine  ComplianceRow
	AMachine bool

	// Comptes : les portées utilisateur, par nom de compte.
	Comptes []ComplianceRow
}

// RegrouperParMachine réunit les lignes d'une même machine, et trie.
func RegrouperParMachine(rows []ComplianceRow, maintenant time.Time) []LigneMachine {
	rang := map[string]int{}
	var out []LigneMachine
	for _, r := range rows {
		i, vue := rang[r.ComputeurID]
		if !vue {
			i = len(out)
			rang[r.ComputeurID] = i
			out = append(out, LigneMachine{ComputeurID: r.ComputeurID})
		}
		// Tout ce qui n'est pas une portée utilisateur tient lieu de portée
		// machine : la portée machine elle-même, et la ligne « ? » d'une machine
		// qui n'a jamais rapporté.
		if r.Scope == string(gpo.ScopeUser) {
			out[i].Comptes = append(out[i].Comptes, r)
			continue
		}
		out[i].Machine, out[i].AMachine = r, true
	}
	for i := range out {
		comptes := out[i].Comptes
		sort.SliceStable(comptes, func(a, b int) bool { return comptes[a].TargetUser < comptes[b].TargetUser })
	}
	TrierMachines(out, maintenant)
	return out
}

// reference rend la ligne qui date la machine : sa portée machine, ou à défaut
// le rapport le plus récent d'un de ses comptes.
func (l LigneMachine) reference() ComplianceRow {
	if l.AMachine {
		return l.Machine
	}
	var r ComplianceRow
	for _, c := range l.Comptes {
		if c.ReportedAt.After(r.ReportedAt) {
			r = c
		}
	}
	return r
}

// Fraicheur : la machine rapporte-t-elle encore ?
//
// Jugée sur la portée MACHINE. Une portée utilisateur ne rapporte qu'à la
// connexion : son ancienneté dit depuis quand la personne n'est pas venue, pas
// que l'agent s'est tu.
func (l LigneMachine) Fraicheur(maintenant time.Time) EtatRapport {
	return l.reference().Fraicheur(maintenant)
}

// Silencieuse : on ne sait plus ce que cette machine applique.
func (l LigneMachine) Silencieuse(maintenant time.Time) bool {
	return l.Fraicheur(maintenant) != RapportAJour
}

// VuLe est la date du dernier rapport de la machine.
func (l LigneMachine) VuLe() time.Time { return l.reference().ReportedAt }

// toutes rend les portées de la machine, la sienne d'abord.
func (l LigneMachine) toutes() []ComplianceRow {
	out := make([]ComplianceRow, 0, len(l.Comptes)+1)
	if l.AMachine {
		out = append(out, l.Machine)
	}
	return append(out, l.Comptes...)
}

// EnEchec : au moins un module en échec, sur n'importe quelle portée.
func (l LigneMachine) EnEchec() bool {
	for _, r := range l.toutes() {
		if r.ModulesFailed > 0 {
			return true
		}
	}
	return false
}

// Ecarts additionne les écarts constatés sur toutes les portées.
func (l LigneMachine) Ecarts() int {
	n := 0
	for _, r := range l.toutes() {
		n += r.DriftCount
	}
	return n
}

// NonVerifiee : au moins une portée appliquée que personne n'a vérifiée.
func (l LigneMachine) NonVerifiee() bool {
	for _, r := range l.toutes() {
		if r.NonVerifiee() {
			return true
		}
	}
	return false
}

// compteARemonter dit si la portée d'un compte a quelque chose à montrer dans
// la liste.
func compteARemonter(r ComplianceRow) bool {
	return r.DriftCount > 0 || r.ModulesFailed > 0 || r.NonVerifiee()
}

// ARemonter rend les comptes à faire figurer SOUS la ligne de la machine.
//
// « Non vérifié » remonte aussi, alors que ce n'est pas un écart : c'est le cas
// où l'on ne sait pas, et le résumé le compte. Un chiffre dans le résumé qu'on
// ne retrouve sur aucune ligne ne sert à rien.
func (l LigneMachine) ARemonter() []ComplianceRow {
	var out []ComplianceRow
	for _, c := range l.Comptes {
		if compteARemonter(c) {
			out = append(out, c)
		}
	}
	return out
}

// EtatDesComptes résume les portées utilisateur en une cellule.
//
// « - » quand personne ne s'est connecté : une machine sans compte n'a pas
// « zéro compte conforme », elle n'a pas de compte.
func (l LigneMachine) EtatDesComptes() string {
	total := len(l.Comptes)
	if total == 0 {
		return "-"
	}
	ecart, echec, nonVerifies := 0, 0, 0
	for _, c := range l.Comptes {
		switch {
		case c.DriftCount > 0:
			ecart++
		case c.ModulesFailed > 0:
			echec++
		case c.NonVerifiee():
			nonVerifies++
		}
	}
	var parts []string
	if ecart > 0 {
		parts = append(parts, fmt.Sprintf("%d en écart", ecart))
	}
	if echec > 0 {
		parts = append(parts, fmt.Sprintf("%d en échec", echec))
	}
	if nonVerifies > 0 {
		parts = append(parts, fmt.Sprintf("%d non vérifié(s)", nonVerifies))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d ok", total)
	}
	return strings.Join(parts, ", ") + fmt.Sprintf(" sur %d", total)
}

// ARetenirDansLaVueDesEcarts : la machine figure-t-elle dans « drift » ?
//
// Un écart sur n'importe quelle portée, ou le silence de la machine — même
// raison que pour une ligne : ne pas savoir est le cas qu'on veut le moins
// cacher.
func (l LigneMachine) ARetenirDansLaVueDesEcarts(maintenant time.Time) bool {
	return l.Ecarts() > 0 || l.Silencieuse(maintenant)
}

// TrierMachines place devant ce dont on ne sait rien, puis ce qui va mal.
//
// Le même ordre que TrierConformite, porté à la machine : silence, échec,
// écarts du plus grand nombre au plus petit, puis l'identifiant. Le pire état
// d'une portée est celui de la machine.
func TrierMachines(lignes []LigneMachine, maintenant time.Time) {
	sort.SliceStable(lignes, func(i, j int) bool {
		a, b := lignes[i], lignes[j]
		if sa, sb := a.Silencieuse(maintenant), b.Silencieuse(maintenant); sa != sb {
			return sa
		}
		if ea, eb := a.EnEchec(), b.EnEchec(); ea != eb {
			return ea
		}
		if a.Ecarts() != b.Ecarts() {
			return a.Ecarts() > b.Ecarts()
		}
		return a.ComputeurID < b.ComputeurID
	})
}
