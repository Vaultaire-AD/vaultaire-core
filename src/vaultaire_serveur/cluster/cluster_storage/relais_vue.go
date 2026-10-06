package clusterstorage

import (
	"fmt"
	"strings"
	"time"
)

// Ce que la page Cluster et la commande affichent des relais d'un proxy —
// TO-DO 141.
//
// # Trois états, et pourquoi pas deux
//
// Le core peut DEMANDER un relais ; seul le proxy sait s'il l'a obtenu. Le
// port est peut-être déjà pris, ou le proxy tourne sans le droit d'ouvrir un
// port bas. Entre « demandé » et « ça tourne », il y a donc un aller-retour, et
// une réponse qui peut être non :
//
//	demandé    le core le veut, le proxy n'a pas encore dit ce qu'il en est
//	appliqué   le proxy l'a ouvert, avec cette configuration
//	refusé     le proxy ne peut pas, et dit pourquoi
//
// Afficher « enregistré » à la place des trois laisserait croire qu'un relais
// existe parce qu'on vient de le taper.

// États d'un relais dans la vue.
const (
	// EtatDuFichier : le core ne pilote pas ce proxy. Le relais vient de son
	// fichier de configuration, et il tourne.
	EtatDuFichier = "fichier"
	EtatDemande   = "demande"
	EtatApplique  = "applique"
	EtatRefuse    = "refuse"
)

// FraicheurCompteRendu est l'âge au-delà duquel un compte rendu ne décrit plus
// l'état courant. Trois fois la cadence à laquelle un proxy rend compte.
const FraicheurCompteRendu = 3 * time.Minute

// RelaisVue est un relais tel qu'on l'affiche.
type RelaisVue struct {
	RelaisConfig

	Etat  string
	Motif string

	// EcouteEffective et CiblesResolues viennent du proxy : l'adresse
	// réellement ouverte, et vers quoi une connexion partirait maintenant.
	//
	// « CiblesResolues » et non « Cibles » : RelaisConfig, embarquée, porte
	// déjà un champ Cibles — la SOURCE des cibles. Un second du même nom le
	// masquerait, et le gabarit lirait une liste là où il attend une source.
	EcouteEffective string
	CiblesResolues  []string

	// Mesure porte les compteurs du relais (TO-DO 108), s'il en remonte.
	Mesure *RelaisMesure

	// Effectif est la configuration telle que le proxy l'APPLIQUE, défauts
	// résolus. Nil tant qu'il ne l'a pas rapportée.
	//
	// Séparé de la demande, et non fondu dedans : la demande garde ses zéros —
	// « le défaut du proxy » — parce que c'est elle que le formulaire
	// réenregistre. La remplir avec les valeurs du proxy figerait un défaut en
	// réglage à la première modification d'autre chose.
	Effectif *RelaisConfig
}

// Limites rend les quatre réglages tels qu'ils s'appliquent : ceux du proxy
// s'il les a rapportés, ceux de la demande sinon, où zéro se lit « défaut ».
func (r RelaisVue) Limites() string {
	c := r.RelaisConfig
	if r.Effectif != nil {
		c = *r.Effectif
	}
	ou := func(n int, unite string) string {
		if n == 0 {
			return "défaut du proxy"
		}
		return fmt.Sprintf("%d%s", n, unite)
	}
	return fmt.Sprintf("délai de connexion : %s ; inactivité : %s ; connexions au plus : %s ; par source : %s",
		ou(c.DelaiConnexionSecondes, " s"), ou(c.InactiviteSecondes, " s"), ou(c.MaxConnexions, ""), ou(c.MaxParSource, ""))
}

// LibelleEtat rend l'état en clair.
func (r RelaisVue) LibelleEtat() string {
	switch r.Etat {
	case EtatApplique:
		return "appliqué"
	case EtatDemande:
		return "demandé"
	case EtatRefuse:
		return "refusé"
	default:
		return "du fichier"
	}
}

// SourceLisible décrit d'où viennent les cibles.
func (r RelaisConfig) SourceLisible() string {
	switch {
	case r.Cibles.Source == SourceCores:
		if r.Cibles.Port > 0 {
			return fmt.Sprintf("les cores du cluster, port %d", r.Cibles.Port)
		}
		if r.Type == RelaisLDAPS {
			return "les cores du cluster, port 636"
		}
		return "les cores du cluster"
	case r.Cibles.Source == SourceListe:
		return "liste fixe : " + strings.Join(r.Cibles.Adresses, ", ")
	case strings.HasPrefix(r.Cibles.Source, SourceService):
		return "les services « " + r.TypeDeService() + " » du cluster"
	}
	return r.Cibles.Source
}

// CiblesLisibles rend les cibles résolues, ou dit qu'il n'y en a pas.
func (r RelaisVue) CiblesLisibles() string {
	if len(r.CiblesResolues) == 0 {
		return ""
	}
	return strings.Join(r.CiblesResolues, ", ")
}

// VueRelais est l'état des relais d'un proxy.
type VueRelais struct {
	// Connu : le proxy a rendu compte au moins une fois. Faux pour un proxy
	// d'une version antérieure à la 2.2, ou jamais vu depuis.
	Connu bool

	// Pilote : le core a une liste pour ce proxy. Revision est la sienne.
	Pilote   bool
	Revision int

	// RevisionAppliquee et Origine : ce que le proxy dit appliquer.
	RevisionAppliquee int
	Origine           string

	// PilotageAccepte : le proxy accepte d'être piloté.
	PilotageAccepte bool
	PortAnnonce     int

	// Refus : le motif du refus de la liste ENTIÈRE, s'il y en a un.
	Refus string

	// Recu et Frais : l'âge du compte rendu.
	Recu  time.Time
	Frais bool

	ModifiePar string
	ModifieLe  time.Time

	// Relais est ce que le core demande, avec l'état de chaque demande — ou,
	// si le core ne pilote pas, ce que le proxy tient de son fichier.
	Relais []RelaisVue

	// EnService est ce qui tourne RÉELLEMENT sur le proxy quand cela diffère
	// de la demande : la révision n'est pas encore appliquée, ou elle a été
	// refusée. Vide quand la demande est appliquée.
	EnService []RelaisVue
}

// AJour dit si le proxy applique la révision demandée.
func (v VueRelais) AJour() bool {
	return v.Pilote && v.Connu && v.Origine == OrigineCore && v.RevisionAppliquee == v.Revision
}

// Resume dit en une ligne où en est le proxy.
func (v VueRelais) Resume() string {
	switch {
	case !v.Connu && !v.Pilote:
		return "ce proxy n'a pas rendu compte de ses relais — version antérieure à la 2.2, ou jamais vu depuis"
	case !v.Connu:
		return fmt.Sprintf("révision %d demandée, le proxy n'a pas encore rendu compte", v.Revision)
	case !v.Pilote && v.Origine == OrigineCore:
		return "le core a rendu la main, le proxy n'a pas encore réappliqué son fichier"
	case !v.Pilote:
		return "configuration du fichier du proxy — le core ne pilote pas ces relais"
	case v.Refus != "":
		return fmt.Sprintf("révision %d REFUSÉE par le proxy : %s", v.Revision, v.Refus)
	case v.AJour():
		return fmt.Sprintf("révision %d appliquée par le proxy", v.Revision)
	case v.Origine == OrigineCore:
		return fmt.Sprintf("révision %d demandée, le proxy applique encore la révision %d", v.Revision, v.RevisionAppliquee)
	default:
		return fmt.Sprintf("révision %d demandée, le proxy applique encore son fichier", v.Revision)
	}
}

// ComposerVueRelais met en regard ce que le core demande et ce que le proxy
// rapporte.
//
// demande et revision viennent de la base ; revision vaut zéro quand le core
// ne pilote pas. rapport est nil si le proxy n'a jamais rendu compte.
func ComposerVueRelais(demande []RelaisConfig, revision int, rapport *CompteRenduRelais,
	mesures []RelaisMesure, maintenant time.Time) VueRelais {

	v := VueRelais{Pilote: revision > 0, Revision: revision}

	parNom := map[string]*RelaisMesure{}
	for i := range mesures {
		parNom[mesures[i].Nom] = &mesures[i]
	}
	rapportes := map[string]RelaisRapporte{}
	if rapport != nil {
		v.Connu = true
		v.RevisionAppliquee = rapport.Revision
		v.Origine = rapport.Origine
		v.PilotageAccepte = rapport.Pilotage
		v.PortAnnonce = rapport.PortAnnonce
		v.Recu = rapport.Recu
		v.Frais = !rapport.Recu.IsZero() && maintenant.Sub(rapport.Recu) <= FraicheurCompteRendu
		for _, r := range rapport.Relais {
			rapportes[r.Nom] = r
		}
	}

	duRapport := func(etatActif string) []RelaisVue {
		if rapport == nil {
			return nil
		}
		out := make([]RelaisVue, 0, len(rapport.Relais))
		for _, r := range rapport.Relais {
			vue := RelaisVue{RelaisConfig: r.RelaisConfig, Etat: etatActif, Motif: r.Motif,
				EcouteEffective: r.EcouteEffective, CiblesResolues: r.CiblesResolues, Mesure: parNom[r.Nom]}
			if r.Statut == StatutRelaisRefuse {
				vue.Etat = EtatRefuse
			} else {
				effectif := r.RelaisConfig
				vue.Effectif = &effectif
			}
			out = append(out, vue)
		}
		return out
	}

	if !v.Pilote {
		// Le core ne pilote pas : ce qu'on montre est ce que le proxy tient.
		v.Relais = duRapport(EtatDuFichier)
		return v
	}

	refusEntier := rapport != nil && rapport.RevisionRefusee == revision && rapport.Refus != ""
	if refusEntier {
		v.Refus = rapport.Refus
	}
	aJour := v.AJour()

	for _, d := range demande {
		vue := RelaisVue{RelaisConfig: d, Etat: EtatDemande, Mesure: nil}
		switch {
		case refusEntier:
			vue.Etat, vue.Motif = EtatRefuse, "la liste entière a été refusée par le proxy"
		case aJour:
			if r, ok := rapportes[d.Nom]; ok {
				vue.EcouteEffective, vue.CiblesResolues = r.EcouteEffective, r.CiblesResolues
				if r.Statut == StatutRelaisActif {
					vue.Etat = EtatApplique
					vue.Mesure = parNom[d.Nom]
					effectif := r.RelaisConfig
					vue.Effectif = &effectif
				} else {
					vue.Etat, vue.Motif = EtatRefuse, r.Motif
				}
			}
		}
		v.Relais = append(v.Relais, vue)
	}

	if !aJour {
		// Ce qui tourne vraiment, pendant que la demande n'est pas appliquée.
		etat := EtatDuFichier
		if v.Origine == OrigineCore {
			etat = EtatApplique
		}
		v.EnService = duRapport(etat)
	}
	return v
}
