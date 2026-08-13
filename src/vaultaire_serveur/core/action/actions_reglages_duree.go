package action

import (
	"fmt"
	"strconv"

	"vaultaire/core/permission"
	"vaultaire/core/reglages"
)

// Actions sur les durées d'exploitation.
//
// # La clé retenue
//
// `write:server`, la même que le mode debug et la purge des sessions. Ce sont
// des réglages du SERVEUR, pas des entités de l'annuaire : aucun domaine ne les
// porte, et une délégation par domaine n'aurait rien à quoi s'appliquer.
//
// La lecture emprunte `read:log` plutôt qu'une clé neuve. Les deux répondent à
// « puis-je regarder comment ce serveur est réglé », et créer un
// `read:server` pour deux actions ajouterait une clé de plus à accorder dans
// toutes les permissions existantes — donc un droit qui manque partout jusqu'à
// ce que quelqu'un s'en aperçoive.

// EnregistrerActionsDuree ajoute la consultation et le réglage des durées.
func EnregistrerActionsDuree(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "settings.list",
		CleRBAC: permission.ActionReadLog,
		Portee:  PorteeGlobale,
		FiltreInutile: "un réglage de durée n'appartient à aucun domaine ; il n'y " +
			"a pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les durées d'exploitation et leurs valeurs",
		Executer: listerDurees,
	})

	r.MustEnregistrer(Definition{
		Nom:      "settings.set",
		CleRBAC:  permission.ActionWriteServer,
		Portee:   PorteeGlobale,
		Resume:   "règle une durée d'exploitation",
		Executer: reglerDuree,
	})

	r.MustEnregistrer(Definition{
		Nom:      "settings.reset",
		CleRBAC:  permission.ActionWriteServer,
		Portee:   PorteeGlobale,
		Resume:   "ramène une durée à son défaut codé",
		Executer: reinitialiserDuree,
	})
}

func listerDurees(_ Appelant, _ Params) (Resultat, error) {
	etats := reglages.EtatCourant()

	modifies := 0
	for _, e := range etats {
		if !e.AuDefaut {
			modifies++
		}
	}

	return Resultat{
		Message: fmt.Sprintf("%d durée(s) d'exploitation, dont %d modifiée(s).",
			len(etats), modifies),
		Donnees: etats,
	}, nil
}

func reglerDuree(a Appelant, p Params) (Resultat, error) {
	cle := p.Get("setting")
	if cle == "" {
		return Resultat{}, fmt.Errorf("clé de réglage requise. Connues : %s", reglages.Cles())
	}

	d, connue := reglages.DefinitionDe(cle)
	if !connue {
		// La liste des clés est donnée dans le refus. Sans elle, la seule façon
		// de retrouver le nom exact serait de relancer une autre commande — et
		// c'est le moment où l'on a le plus besoin de l'information.
		return Resultat{}, fmt.Errorf("réglage %q inconnu. Connues : %s", cle, reglages.Cles())
	}

	brut := p.Get("value")
	if brut == "" {
		return Resultat{}, fmt.Errorf("valeur requise, entre %d et %d %s", d.Min, d.Max, d.Unite)
	}
	valeur, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur %q invalide : ce n'est pas un nombre entier de %s", brut, d.Unite)
	}

	ancienne := reglages.Valeur(cle)
	if err := reglages.Ecrire(cle, valeur, a.Username); err != nil {
		return Resultat{}, err
	}

	// Le compte rendu dit la valeur PRÉCÉDENTE et quand le changement prend
	// effet. Sans cela, un exploitant qui règle une cadence puis regarde les
	// journaux ne saurait pas s'il doit encore attendre.
	return Resultat{
		Message: fmt.Sprintf(
			"%s : %d %s → %d %s.\nPrend effet au prochain tour de la boucle, sans redémarrage.\n%s",
			cle, ancienne, d.Unite, valeur, d.Unite, d.Consequence),
		Donnees: map[string]any{"setting": cle, "value": valeur, "previous": ancienne},
	}, nil
}

func reinitialiserDuree(a Appelant, p Params) (Resultat, error) {
	cle := p.Get("setting")
	if cle == "" {
		return Resultat{}, fmt.Errorf("clé de réglage requise. Connues : %s", reglages.Cles())
	}
	d, connue := reglages.DefinitionDe(cle)
	if !connue {
		return Resultat{}, fmt.Errorf("réglage %q inconnu. Connues : %s", cle, reglages.Cles())
	}

	if err := reglages.Reinitialiser(cle, a.Username); err != nil {
		return Resultat{}, err
	}
	return Resultat{
		Message: fmt.Sprintf("%s ramené à son défaut : %d %s.", cle, d.Defaut, d.Unite),
		Donnees: map[string]any{"setting": cle, "value": d.Defaut},
	}, nil
}
