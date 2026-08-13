package dbgpo

import (
	"fmt"
	"time"
)

// Libellés de la conformité, partagés par la ligne de commande et le portail.
//
// # Pourquoi ils ne vivent pas dans les façades
//
// Ils y ont vécu, en privé, dans `commandgpo`. Tant qu'il n'y avait qu'une
// façade, cela n'avait aucune conséquence. Le jour où le portail a eu sa page de
// conformité, il n'avait que deux choix : les recopier, ou les remonter.
//
// Recopier aurait produit deux vues qui disent **presque** la même chose. Presque
// est le pire cas : personne ne remarque l'écart tant qu'il est petit, et quand
// il grandit, on ne sait plus laquelle des deux avait raison. Un administrateur
// qui lit « non vérifié » en ligne de commande et « conforme » sur le portail ne
// sait plus quoi croire — et c'est justement la vue qu'il consulte quand quelque
// chose ne va pas.
//
// Ces fonctions accompagnent `Fraicheur`, `TrierConformite` et `ResumerParc`,
// qui étaient déjà ici pour la même raison : ce sont des DÉCISIONS sur des
// lignes, pas de la mise en page. La mise en page — colonnes, largeurs, HTML —
// reste à chaque façade.
//
// # Pourquoi elles n'appellent pas time.Now()
//
// Comme `Fraicheur` : un rendu qui prend l'heure lui-même ne se teste qu'en
// attendant réellement, c'est-à-dire jamais.

// EtatConformite rend l'état de conformité en une cellule.
//
// Trois cas, et le premier compte : « jamais vérifié » n'est PAS « conforme ».
// Afficher un zéro rassurant pour une machine que personne n'a scannée est la
// seule erreur d'affichage qui puisse faire conclure à tort qu'un parc va bien.
func (r ComplianceRow) EtatConformite() string {
	if !r.DriftAt.Valid {
		return "non vérifié"
	}
	if r.DriftCount == 0 {
		return fmt.Sprintf("ok (%d)", r.DriftChecked)
	}
	return fmt.Sprintf("%d écart(s)", r.DriftCount)
}

// ModulesAppliques rend « appliqués / total », ou « - » si rien n'a été dit.
//
// « 0/0 » se lit comme « aucun module à appliquer », c'est-à-dire comme une
// réussite. Une machine qui n'a jamais rapporté n'a rien appliqué du tout, ce
// qui n'est pas la même chose et se dit autrement.
func (r ComplianceRow) ModulesAppliques() string {
	if r.JamaisRapporte {
		return "-"
	}
	return fmt.Sprintf("%d/%d", r.ModulesTotal-r.ModulesFailed, r.ModulesTotal)
}

// AgeRelatif rend une date en durée écoulée.
//
// Un horodatage absolu oblige à faire la soustraction de tête, et c'est
// précisément ce qu'on veut savoir : est-ce que cette machine rapporte encore ?
func AgeRelatif(t time.Time, maintenant time.Time) string {
	if t.IsZero() {
		return "jamais"
	}
	d := maintenant.Sub(t.UTC())
	switch {
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %dmin", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("il y a %dh", int(d.Hours()))
	default:
		return fmt.Sprintf("il y a %dj", int(d.Hours())/24)
	}
}

// ResumeLisible rend l'état du parc en une phrase.
//
// Compté en MACHINES, pas en lignes — voir ResumerParc. Le total gonflerait à
// proportion du nombre d'utilisateurs connectés, et « 47 échecs » sur douze
// machines ne veut rien dire.
func (r ResumeParc) Lisible() string {
	var parties []string
	if r.Jamais > 0 {
		parties = append(parties, fmt.Sprintf("%d jamais rapporté", r.Jamais))
	}
	if r.EnRetard > 0 {
		parties = append(parties, fmt.Sprintf("%d en retard", r.EnRetard))
	}
	if r.EnEchec > 0 {
		parties = append(parties, fmt.Sprintf("%d en échec", r.EnEchec))
	}
	if r.AvecEcarts > 0 {
		parties = append(parties, fmt.Sprintf("%d avec écarts", r.AvecEcarts))
	}
	if len(parties) == 0 {
		return fmt.Sprintf("%d machine(s), toutes à jour.", r.Machines)
	}
	return fmt.Sprintf("%d machine(s) : %s.", r.Machines, joindre(parties))
}

func joindre(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ARetenirDansLaVueDesEcarts dit si une ligne doit figurer dans « drift ».
//
// Une machine MUETTE y figure alors qu'elle a zéro écart constaté — non parce
// qu'elle est saine, mais parce que plus personne ne regarde. La retirer d'une
// vue qui cherche les problèmes reviendrait à cacher le seul cas où l'on ne sait
// rien.
//
// Partagé entre les deux façades pour la même raison que les libellés : deux
// filtres écrits séparément finiraient par ne pas montrer les mêmes machines,
// et l'écart porterait précisément sur le cas le plus délicat.
func (r ComplianceRow) ARetenirDansLaVueDesEcarts(maintenant time.Time) bool {
	return r.DriftCount > 0 || r.Silencieuse(maintenant)
}
