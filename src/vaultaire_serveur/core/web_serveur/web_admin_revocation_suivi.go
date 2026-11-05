package webserveur

import (
	"fmt"

	act "vaultaire/core/action"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/permission"
)

// Le suivi d'une révocation sur la fiche d'un compte — TO-DO 164.
//
// # Ce que cette page ne décide pas
//
// Ni l'ordre des machines, ni le libellé d'un état, ni le décompte, ni ce qui
// se dit d'une machine « en attente ». Tout cela vient de db_revocation, et
// `vlt kill -u <compte> --status` emprunte les mêmes fonctions : c'est la vue
// qu'on ouvre pendant un incident, et deux façades qui ne diraient pas la même
// chose d'une même machine feraient douter des deux.
//
// La lecture passe par l'action `revocation.get_status` : même clé, même
// portée, même réduction au périmètre de l'appelant que la ligne de commande.

// cleSuiviRevocation est la clé de l'action, redite ici pour le contrôle
// préalable — voir suiviPourLaFiche.
const cleSuiviRevocation = "read:status:user"

// cibleSuiviVue est une machine visée par un ordre.
type cibleSuiviVue struct {
	Machine string
	Etat    string
	Remises int
	Echange string
	Detail  string
	// AReprendre fait ressortir la ligne : l'ordre n'y est pas appliqué et lui
	// sera encore remis.
	AReprendre bool
}

// ordreSuiviVue est un ordre et ses cibles, mis en forme.
type ordreSuiviVue struct {
	ID       int
	Action   string
	Motif    string
	Par      string
	Le       string
	LevePar  string
	Decompte string
	Masquees int
	// Reste : machines où l'ordre n'est pas appliqué et sera encore remis.
	Reste  int
	Cibles []cibleSuiviVue
	// Ouvert déplie l'ordre à l'affichage : le plus récent, et tout ordre qui
	// n'est pas réglé.
	Ouvert bool
}

// vueDuSuivi met un suivi en forme pour le gabarit. Pure : les données sont
// déjà lues, filtrées et triées.
func vueDuSuivi(s dbrevocation.Suivi) []ordreSuiviVue {
	out := make([]ordreSuiviVue, 0, len(s.Ordres))
	for i, o := range s.Ordres {
		decompte := dbrevocation.Compter(o.Cibles)
		v := ordreSuiviVue{
			ID:       o.ID,
			Action:   o.Mode.Label(),
			Motif:    o.Reason.Label(),
			Par:      o.IssuedBy,
			Le:       o.IssuedAt.Format("2006-01-02 15:04:05"),
			LevePar:  o.LiftedBy,
			Decompte: decompte.Lisible(),
			Masquees: o.Masquees,
			Reste:    decompte.ResteAFaire(),
		}
		v.Ouvert = i == 0 || v.Reste > 0
		for _, c := range o.Cibles {
			v.Cibles = append(v.Cibles, cibleSuiviVue{
				Machine:    c.ComputeurID,
				Etat:       c.Status.Libelle(),
				Remises:    c.Attempts,
				Echange:    c.Echange(),
				Detail:     c.Commentaire(),
				AReprendre: c.Status.ARejouer(),
			})
		}
		out = append(out, v)
	}
	return out
}

// suiviPourLaFiche lit le suivi d'un compte pour sa fiche.
//
// Rend les ordres mis en forme, le nombre d'ordres plus anciens non détaillés,
// et — quand le suivi ne peut pas être montré — la raison à afficher à sa
// place. Une fiche ne doit pas échouer parce que cette lecture échoue.
//
// # Le contrôle préalable
//
// La section « Désactivation d'urgence » s'affiche à qui détient
// write:killswitch. Le suivi demande read:status:user, et l'on peut avoir
// l'un sans l'autre. Appeler l'action sans vérifier ferait écrire au journal
// un refus SECURITY à chaque ouverture de la fiche, pour quelqu'un qui n'a
// rien tenté. On regarde donc d'abord si l'appelant détient la clé QUELQUE
// PART ; le contrôle qui compte — sur les domaines du compte — reste celui de
// l'action.
func suiviPourLaFiche(appelant string, groupIDs []int, compte string) (ordres []ordreSuiviVue, plusAnciens int, indisponible string) {
	if !permission.HasActionAnywhere(groupIDs, cleSuiviRevocation) {
		return nil, 0, fmt.Sprintf("Le détail par machine demande la permission %s.", cleSuiviRevocation)
	}
	res, err := ExecuterLecture("revocation.get_status", appelant, groupIDs, act.Params{"username": compte})
	if err != nil {
		return nil, 0, "Le détail par machine n'a pas pu être lu : " + MessageDActionPourAffichage(res, err)
	}
	suivi, ok := res.Donnees.(dbrevocation.Suivi)
	if !ok {
		return nil, 0, ""
	}
	return vueDuSuivi(suivi), suivi.PlusAnciens, ""
}
