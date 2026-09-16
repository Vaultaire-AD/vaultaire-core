package display

import (
	"fmt"

	dbgpo "vaultaire/core/database/db_gpo"
)

// DisplayAllGPOs liste les GPO : portée, version, activation, modules et
// groupes liés.
//
// L'ancienne version rendait un bloc de six lignes par GPO, séparé par des
// tirets. Sur un parc qui en compte trente, cela fait deux cents lignes qu'on
// ne peut ni comparer ni parcourir des yeux — alors que la question posée est
// presque toujours « laquelle est active, et sur quels groupes ».
//
// Une table répond à cette question en une écran. Le détail des paramètres
// reste le rôle de DisplayGPOByName.
func DisplayAllGPOs(policies []dbgpo.PolicySummary) string {
	if len(policies) == 0 {
		return "Aucune GPO."
	}

	t := NouvelleTable("ID", "Nom", "Portée", "Version", "État", "Dérive", "Modules", "Groupes")
	actives := 0
	for _, p := range policies {
		if p.Enabled {
			actives++
		}
		t.Ajouter(
			fmt.Sprintf("%d", p.ID),
			Valeur(p.Name),
			Valeur(string(p.Scope)),
			fmt.Sprintf("v%d", p.Version),
			etatGPO(p.Enabled),
			// La valeur nue suffit dans un tableau : la phrase complète est sur
			// la fiche. Une GPO en « audit » se repère ici d'un coup d'œil, ce
			// qui est la question qu'on se pose en balayant la liste.
			Valeur(string(p.EffectiveDriftMode())),
			fmt.Sprintf("%d", p.ModuleCount),
			Liste(p.Groups),
		)
	}

	// Le compte des GPO ACTIVES en tête : une GPO désactivée ne s'applique
	// nulle part, et confondre les deux fait chercher longtemps pourquoi une
	// règle « existe » sans effet.
	return fmt.Sprintf("%d GPO, dont %d active(s)\n\n%s", len(policies), actives, t.String())
}

func etatGPO(active bool) string {
	if active {
		return "active"
	}
	return "désactivée"
}
