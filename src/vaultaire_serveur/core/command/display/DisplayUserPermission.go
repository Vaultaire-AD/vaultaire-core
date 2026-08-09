package display

import (
	"fmt"
	"sort"
	"strings"

	"vaultaire/core/storage"
)

// Affichage d'une permission utilisateur.
//
// # Ce qui manquait
//
// L'ancienne version n'affichait que les colonnes HISTORIQUES — none, auth,
// compare, search, web_admin — et se terminait par :
//
//	(Actions RBAC catégorie:action:objet dans user_permission_action,
//	 voir détail admin)
//
// Autrement dit, elle renvoyait l'utilisateur vers l'interface web pour
// connaître le contenu réel de la permission. Or ces actions RBAC sont
// précisément ce qui décide de ce que la permission autorise : les colonnes
// historiques ne servent plus qu'à l'annuaire LDAP et à l'accès web.
//
// `get -p -u lecture` ne répondait donc pas à « que permet cette permission ? ».
//
// # Sur la présentation
//
// Les actions sont groupées par objet — user, group, client, permission, gpo —
// parce que c'est ainsi qu'on les lit : « qu'est-ce que cette permission
// autorise sur les utilisateurs ? ». Une liste alphabétique mélangerait
// read:get:user et read:get:group entre deux write.
//
// Les actions à « nil » sont affichées elles aussi. Les masquer donnerait une
// fiche plus courte mais impossible à interpréter : on ne saurait pas si une
// action absente est refusée ou si l'affichage l'a omise.

// ActionRBAC associe une clé d'action à sa valeur pour une permission.
type ActionRBAC struct {
	Cle    string
	Valeur string
}

// DisplayUserPermission rend la fiche d'une permission utilisateur.
//
// `actions` peut être nil : la fiche affiche alors les seules colonnes
// historiques, avec une note qui dit pourquoi — plutôt qu'une section vide
// qu'on prendrait pour « aucun droit ».
func DisplayUserPermission(permission storage.UserPermission, actions []ActionRBAC) string {
	f := NouvelleFiche("Permission utilisateur — " + permission.Name)

	f.Ajouter("Identifiant", fmt.Sprintf("%d", permission.ID))
	f.Ajouter("Description", permission.Description)

	// --- droits RBAC, groupés par objet ---
	if actions == nil {
		f.AjouterSection("Droits RBAC")
		f.Ajouter("état", "non lus (base indisponible)")
	} else {
		accordees, refusees := trierActions(actions)

		f.AjouterSection(fmt.Sprintf("Droits accordés (%d)", len(accordees)))
		if len(accordees) == 0 {
			f.Ajouter("aucun", "cette permission n'autorise rien")
		}
		for _, a := range accordees {
			f.Ajouter(a.Cle, lisibleValeurAction(a.Valeur))
		}

		// Les droits refusés en fin de fiche : ils sont la majorité, et les
		// mettre en tête noierait les quelques-uns qui comptent.
		if len(refusees) > 0 {
			f.AjouterSection(fmt.Sprintf("Droits non accordés (%d)", len(refusees)))
			f.Ajouter("clés", resumerRefus(refusees))
		}
	}

	// --- colonnes historiques ---
	//
	// Conservées parce qu'elles servent encore : web_admin ouvre l'interface
	// d'administration, et les quatre autres pilotent les opérations LDAP.
	// Séparées des droits RBAC pour qu'on ne les confonde pas.
	f.AjouterSection("Accès historiques (LDAP et interface web)")
	f.Ajouter("web_admin", lisibleValeurAction(permission.Web_admin))
	f.Ajouter("auth", lisibleValeurAction(permission.Auth))
	f.Ajouter("compare", lisibleValeurAction(permission.Compare))
	f.Ajouter("search", lisibleValeurAction(permission.Search))
	f.Ajouter("none", lisibleValeurAction(permission.None))

	return f.String()
}

// trierActions sépare ce qui est accordé de ce qui ne l'est pas, et trie par
// objet puis par clé.
//
// Le tri par objet suit l'ordre de lecture naturel — utilisateurs, groupes,
// machines, permissions, GPO — et non l'ordre alphabétique, qui placerait
// « client » avant « group » sans raison pour le lecteur.
func trierActions(actions []ActionRBAC) (accordees, refusees []ActionRBAC) {
	for _, a := range actions {
		if estAccordee(a.Valeur) {
			accordees = append(accordees, a)
		} else {
			refusees = append(refusees, a)
		}
	}
	sort.Slice(accordees, func(i, j int) bool { return avantPourLaLecture(accordees[i].Cle, accordees[j].Cle) })
	sort.Slice(refusees, func(i, j int) bool { return avantPourLaLecture(refusees[i].Cle, refusees[j].Cle) })
	return accordees, refusees
}

// ordreDesObjets fixe l'ordre de lecture.
var ordreDesObjets = map[string]int{
	"user": 0, "group": 1, "client": 2, "permission": 3, "gpo": 4,
}

func avantPourLaLecture(a, b string) bool {
	oa, ob := rangObjet(a), rangObjet(b)
	if oa != ob {
		return oa < ob
	}
	return a < b
}

func rangObjet(cle string) int {
	parts := strings.Split(cle, ":")
	if len(parts) != 3 {
		// Les actions spéciales — write:dns, write:mfa, read:log — n'ont pas
		// d'objet. Elles passent en fin de liste plutôt que de s'intercaler
		// entre des clés à trois segments.
		return 99
	}
	if r, connu := ordreDesObjets[parts[2]]; connu {
		return r
	}
	return 98
}

// estAccordee dit si une valeur donne effectivement un droit.
//
// « nil » et la chaîne vide valent refus. Tout le reste — « all », ou une liste
// de domaines — accorde quelque chose.
func estAccordee(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v != "" && v != "nil"
}

// lisibleValeurAction traduit les valeurs internes.
//
// « all » et « nil » sont des marqueurs de la base, pas des mots destinés à un
// administrateur. « tous les domaines » et « refusé » disent la même chose sans
// qu'il faille connaître la convention interne.
func lisibleValeurAction(v string) string {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "", "nil":
		return "refusé"
	case "all":
		return "tous les domaines"
	default:
		return v
	}
}

// resumerRefus rend les clés refusées sur une ligne.
//
// Une ligne par clé refusée ferait une fiche de cinquante lignes dont
// quarante-cinq disent « refusé ». Le résumé garde l'information — on peut
// vérifier qu'une clé précise est bien absente des droits accordés — sans
// noyer ce qui compte.
func resumerRefus(refusees []ActionRBAC) string {
	cles := make([]string, 0, len(refusees))
	for _, a := range refusees {
		cles = append(cles, a.Cle)
	}
	return strings.Join(cles, ", ")
}
