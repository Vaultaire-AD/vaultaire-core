package relais

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Les documents échangés avec le core pour le pilotage des relais (TO-DO 141).
//
// # Un format de PROTOCOLE
//
// Le core vit dans un autre module et ne partage aucun code avec celui-ci :
// ce qui compte est la forme de ce qui part, au même titre qu'un numéro de
// trame. Un champ absent vaut sa valeur nulle, des deux côtés — c'est ce qui
// permet d'en ajouter un sans qu'un pair resté en arrière refuse le document.
//
//	04_18  proxy → core   CompteRendu
//	04_19  core → proxy   Demande

// VersionDuDocument est portée par chaque compte rendu. Elle ne change que si
// un champ change de SENS — en ajouter un ne la touche pas.
const VersionDuDocument = 1

// Origines de la configuration qu'un proxy applique.
const (
	// OrigineFichier : le fichier de configuration du proxy.
	OrigineFichier = "fichier"
	// OrigineCore : une liste reçue du core — à l'instant, ou relue au
	// démarrage de la copie que le proxy en garde sur son disque.
	OrigineCore = "core"
)

// CompteRendu est ce qu'un proxy dit de ses relais.
type CompteRendu struct {
	Version int `json:"v"`

	// Revision est celle de la liste du core que le proxy applique. Zéro : il
	// applique son fichier.
	Revision int    `json:"revision"`
	Origine  string `json:"origine"`

	// Pilotage dit si ce proxy accepte d'être piloté. Faux : son fichier
	// porte « pilotage_par_le_core: false », et il le dit pour que le core
	// n'attende pas une application qui ne viendra pas.
	Pilotage bool `json:"pilotage"`

	// PortAnnonce est le port Ducky annoncé au cluster : celui que le relais
	// Ducky doit garder, et que le core ne peut pas changer d'ici.
	PortAnnonce int `json:"port_annonce"`

	// RevisionRefusee et Refus : la dernière liste du core refusée EN ENTIER,
	// et pourquoi. Le core cesse alors de la renvoyer.
	RevisionRefusee int    `json:"revision_refusee,omitempty"`
	Refus           string `json:"refus,omitempty"`

	Relais []RelaisRapporte `json:"relais"`
}

// RelaisRapporte est un relais dans un compte rendu : sa configuration, avec
// les défauts résolus, et ce qu'il en est sur la machine.
type RelaisRapporte struct {
	Relais

	Statut string `json:"statut"`
	Motif  string `json:"motif,omitempty"`
	// EcouteEffective est l'adresse réellement ouverte.
	EcouteEffective string `json:"ecoute_effective,omitempty"`
	// CiblesResolues : vers quoi le relais enverrait une connexion MAINTENANT.
	CiblesResolues []string `json:"cibles_resolues,omitempty"`
}

// Demande est la liste de relais que le core veut voir tourner.
type Demande struct {
	Relais []Relais `json:"relais"`
}

// Composer fait un compte rendu des états d'un parc.
func Composer(etats []Etat) []RelaisRapporte {
	out := make([]RelaisRapporte, 0, len(etats))
	for _, e := range etats {
		out = append(out, RelaisRapporte{Relais: e.Relais, Statut: e.Statut, Motif: e.Motif,
			EcouteEffective: e.Ecoute, CiblesResolues: e.Cibles})
	}
	return out
}

// Encoder rend le compte rendu sur une ligne.
func (c CompteRendu) Encoder() string {
	if c.Relais == nil {
		// « [] » et non « null » : un core qui parcourt la liste n'a pas à
		// distinguer « aucun relais » d'un champ manquant.
		c.Relais = []RelaisRapporte{}
	}
	b, err := json.Marshal(c)
	if err != nil {
		// Aucun champ de cette structure ne peut échouer à s'encoder.
		return "{}"
	}
	return string(b)
}

// LireDemande décode le document d'une 04_19.
//
// Un champ INCONNU est refusé. Le proxy ouvre des ports sur la foi de ce
// document : mieux vaut refuser une liste qu'on ne comprend pas en entier que
// d'en appliquer la moitié qu'on a reconnue.
func LireDemande(document string) (Demande, error) {
	var d Demande
	dec := json.NewDecoder(strings.NewReader(document))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Demande{}, fmt.Errorf("liste de relais du core illisible : %w", err)
	}
	return d, nil
}
