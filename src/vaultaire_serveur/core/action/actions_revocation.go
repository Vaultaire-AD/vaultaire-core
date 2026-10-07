package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/domain"
)

// Lecture du SUIVI d'une révocation — `kill -u <compte> --status` et la fiche
// du compte du portail (TO-DO 164).
//
// # Pourquoi une clé de LECTURE, et pas write:killswitch
//
// Qui déclenche un ordre a évidemment le droit de voir ce qu'il devient, et la
// tentation était de garder la lecture par la clé qui garde le déclenchement.
// Deux raisons de ne pas le faire :
//
//   - le registre trace comme ÉCRITURE toute action dont la clé commence par
//     « write: ». Chaque consultation de la fiche d'un compte aurait écrit au
//     journal « X a fait revocation.get_status sur Y » — une écriture qui n'en
//     est pas une, dans le journal où l'on cherche qui a coupé qui ;
//   - c'est le défaut que ce paquet a déjà corrigé deux fois (write:dns gardant
//     la lecture des zones, write:eyes gardant une lecture) : une clé dont le
//     nom dit le contraire de ce qu'elle protège. Voir où en est un ordre ne
//     donne pas le pouvoir d'en émettre un.
//
// # Pourquoi read:status:user
//
// C'est la clé de « l'état d'un compte sur les machines » : elle garde déjà
// `status -u <compte>`, qui dit où le compte a une session. Le suivi d'un ordre
// répond à la même question vue de l'autre côté — où ce compte travaille-t-il
// encore — et se délègue de la même façon.
//
// # Ce qui est filtré
//
// Le compte est protégé par le contrôle d'accès, sur ses propres domaines.
// Mais un ordre vise des MACHINES, et elles ne sont pas toutes dans le
// périmètre de qui lit : un délégué de paris qui regarde un compte à cheval sur
// paris et lyon ne doit pas apprendre le nom d'un poste de lyon, ni qu'il y
// reste des processus. Les cibles hors périmètre sont retirées et COMPTÉES —
// le total de l'ordre, lui, ne dépend pas de qui le regarde.

// EnregistrerActionsRevocation ajoute la lecture du suivi d'une révocation.
func EnregistrerActionsRevocation(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "revocation.get_status",
		CleRBAC: "read:status:user",
		// Domaines du COMPTE visé. Un compte supprimé par un ordre « hard » n'a
		// plus de domaine : PorteeUtilisateur exige alors le droit global, ce
		// qui est le bon repli — personne d'autre ne peut plus le situer.
		Portee:          PorteeUtilisateur,
		UnDomaineSuffit: true,
		Filtre:          filtrerSuiviRevocation,
		Resume:          "où en est, machine par machine, la révocation d'un compte",
		Executer:        lireSuiviRevocation,
	})
}

// filtrerSuiviRevocation retire des ordres les machines hors du périmètre de
// l'appelant, et les compte.
func filtrerSuiviRevocation(donnees any, perim Perimetre) (any, int) {
	suivi, ok := donnees.(dbrevocation.Suivi)
	if !ok {
		return donnees, 0
	}
	masquees := 0
	// Une copie : le filtre ne modifie pas ce que l'action a rendu.
	ordres := make([]dbrevocation.OrdreSuivi, len(suivi.Ordres))
	for i, o := range suivi.Ordres {
		garde := make([]dbrevocation.TargetRecord, 0, len(o.Cibles))
		for _, c := range o.Cibles {
			if perim.AutoriseUnDes(perim.DomainesDe(EntiteClient, c.ComputeurID)) {
				garde = append(garde, c)
			}
		}
		o.Masquees = len(o.Cibles) - len(garde)
		o.Cibles = garde
		masquees += o.Masquees
		ordres[i] = o
	}
	suivi.Ordres = ordres
	return suivi, masquees
}

func lireSuiviRevocation(_ Appelant, p Params) (Resultat, error) {
	cible := strings.TrimSpace(p.Get("username"))
	if cible == "" {
		return Resultat{}, fmt.Errorf("utilisateur cible requis")
	}
	// Les ordres sont enregistrés sous le nom d'ANNUAIRE, sans domaine — c'est
	// ce que fait le déclenchement. La forme complète, qu'on tape parfois par
	// habitude, désigne le même compte.
	annuaire, _ := domain.ExctractDomainFromUsername(cible)
	if strings.TrimSpace(annuaire) == "" {
		annuaire = cible
	}

	suivi, err := dbrevocation.SuiviPour(database.GetDatabase(), annuaire)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture du suivi de %q : %w", annuaire, err)
	}
	if len(suivi.Ordres) == 0 {
		return Resultat{Message: fmt.Sprintf("Aucun ordre de révocation pour %s.", annuaire), Donnees: suivi}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("%d ordre(s) détaillé(s) pour %s.", len(suivi.Ordres), annuaire),
		Donnees: suivi,
	}, nil
}
