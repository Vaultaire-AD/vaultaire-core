// Package miseajour décide de l'ordre de mise à jour d'un agent — TO-DO 115.
//
// # Le modèle de la révocation, repris tel quel
//
// Poussée opportuniste vers qui est connecté — un échec d'envoi n'est pas une
// erreur, personne ne tient de file — et rattrapage par DEMANDE : l'agent
// demande son ordre (09_01) à chaque connexion. C'est ce qui rend la poussée
// non fiable acceptable, et ce qui fait qu'une machine éteinte trois semaines
// se met à jour à son retour.
//
// Il n'y a pas de table d'ordres. L'ordre se DÉDUIT : la version attendue
// (point 111), la version déclarée, le dernier compte rendu. Un ordre écrit en
// base devrait être tenu d'accord avec ces trois valeurs ; déduit, il l'est
// par construction.
//
// # Les trames
//
//	09_01  demander l'ordre        agent → core    au démarrage et à chaque reconnexion
//	  09_02  ordre                 core → agent    version, dépôt, rétrogradation
//	  09_03  rien à faire          core → agent    motif
//	09_04  compte rendu            agent → core    version, résultat, motif
//	  09_05  accusé                core → agent
//	09_06  ordre poussé            core → agent    même contenu que 09_02
package miseajour

import (
	"fmt"
	"regexp"
	"strings"

	"vaultaire/core/parcversion"
)

// Résultats d'un compte rendu 09_04. Les mêmes chaînes vivent dans l'agent
// (vaultaire_client/miseajour) : des tests jumeaux les figent.
const (
	// ResultatInstalle : la version est en place.
	ResultatInstalle = "installe"
	// ResultatEchec : tentée, et revenue en arrière (porte de santé, point 116).
	ResultatEchec = "echec"
	// ResultatRefuse : l'agent n'a rien tenté — rétrogradation non demandée,
	// signature ou manifeste refusés, ordre illisible.
	ResultatRefuse = "refuse"
	// ResultatNonPrisEnCharge : l'agent ne sait pas se mettre à jour (un agent
	// Windows avant le 118, un agent Linux hors systemd ou pas en root).
	ResultatNonPrisEnCharge = "non_pris_en_charge"
)

// ResultatValide dit si un résultat reçu est connu.
func ResultatValide(r string) bool {
	switch r {
	case ResultatInstalle, ResultatEchec, ResultatRefuse, ResultatNonPrisEnCharge:
		return true
	}
	return false
}

// EstUnEchec : tout résultat qui n'a pas mis la version en place.
func EstUnEchec(r string) bool { return r != "" && r != ResultatInstalle }

// VersionQuiComprend est la première version d'agent qui lit la catégorie 09.
//
// Le core ne POUSSE (09_06) qu'à ces agents : un agent plus ancien n'a pas de
// gestionnaire pour la catégorie, et écrirait un avertissement à chaque
// poussée. La DEMANDE (09_01), elle, prouve d'elle-même que l'agent comprend.
var VersionQuiComprend = parcversion.V(2, 3, 0)

// DepotParDefaut : le dépôt de releases de la configuration d'exemple de Nexus.
const DepotParDefaut = "releases"

// CleReglageDepot : le dépôt nommé dans les ordres, dans server_settings.
const CleReglageDepot = "agent_update_repository"

var formeDepot = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// NormaliserDepot valide un nom de dépôt Nexus — la forme que Nexus accepte.
func NormaliserDepot(saisie string) (string, error) {
	s := strings.TrimSpace(saisie)
	if !formeDepot.MatchString(s) {
		return "", fmt.Errorf("nom de dépôt %q refusé : [a-z0-9._-], 64 caractères au plus", saisie)
	}
	return s, nil
}

// Ordre est le contenu d'une 09_02 ou d'une 09_06.
type Ordre struct {
	Version string // trois nombres
	Depot   string
	// Retrograder autorise une version inférieure à celle en place. Jamais
	// déduit : seul « vlt agent update --downgrade » le pose, une fois.
	Retrograder bool
}

// Contenu rend les lignes de la trame.
func (o Ordre) Contenu() []string {
	r := "non"
	if o.Retrograder {
		r = "oui"
	}
	return []string{o.Version, o.Depot, r}
}

// Situation est ce que le core sait d'une machine au moment de décider.
type Situation struct {
	Declaree    string
	Attendue    parcversion.Attendue
	CompteRendu CompteRendu
	Depot       string
	// RetrogradationDemandee : la dérogation de la machine porte le drapeau
	// « --downgrade » (TO-DO 204). Ne compte que si la version attendue VIENT
	// de cette dérogation : une cible de groupe ou de parc ne rétrograde
	// jamais personne.
	RetrogradationDemandee bool
}

// retrogradationDurable dit si la situation autorise une rétrogradation
// sans geste de plus.
func (s Situation) retrogradationDurable() bool {
	return s.RetrogradationDemandee && s.Attendue.Definie && s.Attendue.Source == parcversion.SourceMachine
}

// CompteRendu est le dernier 09_04 connu.
type CompteRendu struct {
	Version, Resultat, Motif string
}

// Decision est la réponse à une demande : un ordre, ou un motif de ne rien
// faire.
type Decision struct {
	Ordre *Ordre
	Motif string
}

// Decider rend l'ordre d'une machine, ou pourquoi il n'y en a pas.
//
//   - sans cible : rien — c'est le défaut, et une installation ne bouge pas
//     tant que personne n'a posé de cible ;
//   - à jour ou en avance : rien. En avance, elle n'est JAMAIS rétrogradée
//     d'office ; « vlt agent update --downgrade » le demande explicitement ;
//   - en retard ou inconnue : l'ordre, SAUF si le dernier compte rendu de
//     CETTE version est un échec. Sans cette règle, une machine qui échoue
//     recevrait le même ordre à chaque reconnexion, et retenterait sans fin
//     un basculement qui casse — sur un poste dont on veut justement que la
//     session reste ouverte. « vlt agent update » efface le compte rendu.
func Decider(s Situation) Decision {
	switch parcversion.Situer(s.Declaree, s.Attendue) {
	case parcversion.EtatSansCible:
		if s.Attendue.Illisible != "" {
			return Decision{Motif: "cible illisible (" + s.Attendue.Illisible + ") : rien à faire"}
		}
		return Decision{Motif: "aucune version attendue"}
	case parcversion.EtatAJour:
		return Decision{Motif: "à jour (" + s.Attendue.Version.String() + ")"}
	case parcversion.EtatEnAvance:
		if !s.retrogradationDurable() {
			return Decision{Motif: "en avance sur " + s.Attendue.Version.String() +
				" : jamais rétrogradée sans ordre explicite"}
		}
	}
	cible := s.Attendue.Version.String()
	if s.CompteRendu.Version == cible && EstUnEchec(s.CompteRendu.Resultat) {
		return Decision{Motif: fmt.Sprintf("dernier essai de %s : %s (%s) — « vlt agent update » pour relancer",
			cible, s.CompteRendu.Resultat, s.CompteRendu.Motif)}
	}
	depot := s.Depot
	if depot == "" {
		depot = DepotParDefaut
	}
	retrograder := parcversion.Situer(s.Declaree, s.Attendue) == parcversion.EtatEnAvance
	return Decision{Ordre: &Ordre{Version: cible, Depot: depot, Retrograder: retrograder}}
}

// ComprendLaCategorie dit si un agent de cette version lit la catégorie 09.
// Une version illisible : non — on ne pousse pas à l'aveugle.
func ComprendLaCategorie(declaree string) bool {
	v, ok := parcversion.Lire(declaree)
	return ok && !v.Avant(VersionQuiComprend)
}

// LireCompteRendu analyse le contenu d'une 09_04 : version, résultat, motif.
func LireCompteRendu(contenu string) (CompteRendu, error) {
	lignes := strings.Split(strings.ReplaceAll(contenu, "\r", ""), "\n")
	at := func(i int) string {
		if i < len(lignes) {
			return strings.TrimSpace(lignes[i])
		}
		return ""
	}
	c := CompteRendu{Version: at(0), Resultat: at(1), Motif: at(2)}
	if _, ok := parcversion.Lire(c.Version); !ok {
		return CompteRendu{}, fmt.Errorf("09_04 : version illisible %q", c.Version)
	}
	if !ResultatValide(c.Resultat) {
		return CompteRendu{}, fmt.Errorf("09_04 : résultat inconnu %q", c.Resultat)
	}
	return c, nil
}

// DeciderPourRelance est la décision de « vlt agent update » : le compte rendu
// est ignoré (la commande l'efface), et retrograder autorise d'aller vers une
// cible INFÉRIEURE à la version en place.
func DeciderPourRelance(s Situation, retrograder bool) (Decision, error) {
	s.CompteRendu = CompteRendu{}
	etat := parcversion.Situer(s.Declaree, s.Attendue)
	switch {
	case etat == parcversion.EtatSansCible:
		return Decision{}, fmt.Errorf("aucune version attendue pour cette machine : " +
			"« vlt agent target » ou « vlt agent pin » d'abord")
	case etat == parcversion.EtatEnAvance && !retrograder && !s.retrogradationDurable():
		return Decision{Motif: "en avance sur " + s.Attendue.Version.String() +
			" : --downgrade pour la ramener à cette version"}, nil
	case etat == parcversion.EtatEnAvance:
		depot := s.Depot
		if depot == "" {
			depot = DepotParDefaut
		}
		return Decision{Ordre: &Ordre{Version: s.Attendue.Version.String(), Depot: depot, Retrograder: true}}, nil
	}
	return Decider(s), nil
}
