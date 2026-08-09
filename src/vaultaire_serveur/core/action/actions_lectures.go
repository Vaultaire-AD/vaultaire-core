package action

import (
	"fmt"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbgroups "vaultaire/core/database/db_groups"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/storage"
)

// Actions de LECTURE — utilisateurs et groupes.
//
// # Pourquoi les lectures rejoignent le registre
//
// Une lecture ne modifie rien, mais elle décide de ce que quelqu'un a le droit
// de VOIR — la liste des comptes, les clés publiques, la composition des
// groupes. Laisser ce contrôle dans chaque façade, c'est le laisser diverger,
// et l'audit ci-dessous montre que c'était déjà le cas.
//
// # Deux défauts trouvés en portant ces lectures
//
//  1. `get -u <compte>` contrôlait le droit sur les domaines de l'APPELANT et
//     non sur ceux du compte visé :
//
//     domainList, _ := permission.GetDomainListFromUsername(senderUsername)
//
//     Toutes les autres lectures — groupes, machines, permissions, GPO —
//     emploient les domaines de la CIBLE. Un délégué de paris pouvait donc lire
//     la fiche d'un compte de lyon : son droit sur ses propres domaines
//     suffisait, et la cible n'entrait jamais dans la décision.
//
//  2. `get -u -g <groupe>` et `get -u <compte> -k` ne vérifiaient RIEN. La
//     fonction qui les traite n'appelait aucun contrôle : la composition de
//     n'importe quel groupe et les clés publiques de n'importe quel compte
//     étaient lisibles par quiconque atteignait la ligne de commande.
//
// # Ce qui NE change pas
//
// L'exigence de portée reste « un domaine suffit » (UnDomaineSuffit), comme
// avant. Voir ce champ : une entité à cheval sur paris et lyon est
// légitimement VISIBLE par le délégué de paris, sans être modifiable par lui.
// Passer les lectures en « tous les domaines » les aurait durcies d'un coup,
// sans que personne l'ait décidé.

// EnregistrerActionsLecture ajoute les lectures utilisateur et groupe.
func EnregistrerActionsLecture(r *Registre) {
	// --- utilisateurs ---

	r.MustEnregistrer(Definition{
		Nom:             "user.list",
		CleRBAC:         "read:get:user",
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          filtrerUtilisateurs,
		Resume:          "liste tous les utilisateurs",
		Executer:        listerUtilisateurs,
	})

	r.MustEnregistrer(Definition{
		Nom:     "user.get",
		CleRBAC: "read:get:user",
		// Domaines de la CIBLE, pas de l'appelant. C'est le premier des deux
		// défauts corrigés — voir l'en-tête du fichier.
		Portee:          PorteeUtilisateur,
		UnDomaineSuffit: true,
		Resume:          "affiche la fiche d'un utilisateur",
		Executer:        lireUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:     "user.list_keys",
		CleRBAC: "read:get:user",
		Portee:  PorteeUtilisateur,
		// Les clés publiques d'un compte sont une donnée du compte : mêmes
		// domaines, même clé. Elles n'étaient contrôlées nulle part.
		UnDomaineSuffit: true,
		FiltreInutile: "les clés appartiennent à UN compte, déjà couvert par le contrôle " +
			"d'accès sur ses domaines ; une clé n'a pas de domaine propre à filtrer",
		Resume:   "liste les clés publiques SSH d'un utilisateur",
		Executer: listerClesUtilisateur,
	})

	// --- groupes ---

	r.MustEnregistrer(Definition{
		Nom:             "group.list",
		CleRBAC:         "read:get:group",
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          filtrerGroupes,
		Resume:          "liste tous les groupes",
		Executer:        listerGroupes,
	})

	r.MustEnregistrer(Definition{
		Nom:             "group.get",
		CleRBAC:         "read:get:group",
		Portee:          PorteeGroupe,
		UnDomaineSuffit: true,
		Resume:          "affiche la fiche d'un groupe",
		Executer:        lireGroupe,
	})

	r.MustEnregistrer(Definition{
		Nom:     "group.list_users",
		CleRBAC: "read:get:user",
		// Clé « user » et non « group » : ce qui est révélé ici est la liste
		// des COMPTES. Exiger read:get:group aurait laissé un délégué qui n'a
		// que le droit sur les groupes énumérer des utilisateurs qu'il n'a pas
		// le droit de lire un par un.
		Portee:          PorteeGroupe,
		UnDomaineSuffit: true,
		Filtre:          filtrerUtilisateursDeGroupe,
		Resume:          "liste les utilisateurs d'un groupe",
		Executer:        listerUtilisateursDuGroupe,
	})

	r.MustEnregistrer(Definition{
		Nom:             "group.list_clients",
		CleRBAC:         "read:get:client",
		Portee:          PorteeGroupe,
		UnDomaineSuffit: true,
		Filtre:          filtrerMachinesDeGroupe,
		Resume:          "liste les machines d'un groupe",
		Executer:        listerMachinesDuGroupe,
	})
}

// --- filtres de visibilité ---------------------------------------------------
//
// Ils réduisent une liste au périmètre de l'appelant. Le contrôle d'accès a
// déjà eu lieu : ce qui se décide ici n'est pas « a-t-il le droit », mais
// « que contient sa réponse ».
//
// Chacun rend aussi le NOMBRE d'entrées masquées. Sans ce compte, une liste
// tronquée se lit comme une liste complète — et c'est ainsi qu'on croit un
// annuaire vide alors qu'on n'en voit qu'une part.

func filtrerUtilisateurs(donnees any, perim Perimetre) (any, int) {
	users, ok := donnees.([]storage.GetUsers)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.GetUsers, 0, len(users))
	for _, u := range users {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteUtilisateur, u.Username)) {
			garde = append(garde, u)
		}
	}
	return garde, len(users) - len(garde)
}

// filtrerGroupes est le seul cas simple : GroupDetails porte déjà son domaine,
// aucune résolution n'est nécessaire.
func filtrerGroupes(donnees any, perim Perimetre) (any, int) {
	groupes, ok := donnees.([]storage.GroupDetails)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.GroupDetails, 0, len(groupes))
	for _, g := range groupes {
		if perim.AutoriseUnDes([]string{g.DomainName}) {
			garde = append(garde, g)
		}
	}
	return garde, len(groupes) - len(garde)
}

// filtrerUtilisateursDeGroupe masque les MEMBRES hors périmètre.
//
// Le groupe lui-même est déjà couvert par le contrôle d'accès — sans droit sur
// ses domaines, l'action n'a pas lieu. Mais un groupe peut réunir des comptes
// de plusieurs domaines : ceux qui échappent au périmètre restent masqués.
func filtrerUtilisateursDeGroupe(donnees any, perim Perimetre) (any, int) {
	d, ok := donnees.(UtilisateursDeGroupe)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.DisplayUsersByGroup, 0, len(d.Utilisateurs))
	for _, u := range d.Utilisateurs {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteUtilisateur, u.Username)) {
			garde = append(garde, u)
		}
	}
	masquees := len(d.Utilisateurs) - len(garde)
	d.Utilisateurs = garde
	return d, masquees
}

func filtrerMachinesDeGroupe(donnees any, perim Perimetre) (any, int) {
	d, ok := donnees.(MachinesDeGroupe)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.GetClientsByGroup, 0, len(d.Machines))
	for _, c := range d.Machines {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteClient, c.ComputeurID)) {
			garde = append(garde, c)
		}
	}
	masquees := len(d.Machines) - len(garde)
	d.Machines = garde
	return d, masquees
}

// --- utilisateurs ------------------------------------------------------------

func listerUtilisateurs(_ Appelant, _ Params) (Resultat, error) {
	users, err := dbusers.Command_GET_AllUsers(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des utilisateurs : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d utilisateur(s).", len(users)),
		Donnees: users,
	}, nil
}

func lireUtilisateur(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("username")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom d'utilisateur requis")
	}
	info, err := dbusers.Command_GET_UserInfo(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable : %w", nom, err)
	}
	return Resultat{Message: "Utilisateur " + nom + ".", Donnees: info}, nil
}

func listerClesUtilisateur(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("username")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom d'utilisateur requis")
	}
	db := database.GetDatabase()

	id, err := dbusers.Get_User_ID_By_Username(db, nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("utilisateur %q introuvable : %w", nom, err)
	}

	cles, err := dbusers.GetUserKeys(id)
	if err != nil {
		// L'erreur de lecture est distinguée de l'absence de clé.
		//
		// L'ancienne version les confondait : `if err != nil || len(cles) == 0`
		// répondait « aucune clé publique » aussi bien quand la requête avait
		// échoué. Un administrateur en concluait que le compte n'avait pas de
		// clé — alors qu'on ne savait pas.
		return Resultat{}, fmt.Errorf("lecture des clés de %q : %w", nom, err)
	}

	return Resultat{
		Message: fmt.Sprintf("%d clé(s) publique(s) pour %s.", len(cles), nom),
		Donnees: ClesUtilisateur{Username: nom, Cles: cles},
	}, nil
}

// ClesUtilisateur porte le nom du compte avec ses clés.
//
// Les clés seules ne disent pas à qui elles appartiennent, et l'affichage a
// besoin des deux. Une structure plutôt que deux valeurs de retour : Donnees
// n'en porte qu'une.
type ClesUtilisateur struct {
	Username string
	Cles     []storage.PublicKey
}

// --- groupes -----------------------------------------------------------------

func listerGroupes(_ Appelant, _ Params) (Resultat, error) {
	groupes, err := dbgroups.Command_GET_GroupDetails(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des groupes : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d groupe(s).", len(groupes)),
		Donnees: groupes,
	}, nil
}

func lireGroupe(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("group")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	info, err := dbgroups.Command_GET_GroupInfo(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("groupe %q introuvable : %w", nom, err)
	}
	return Resultat{Message: "Groupe " + nom + ".", Donnees: info}, nil
}

func listerUtilisateursDuGroupe(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("group")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	users, err := dbgroups.Command_GET_UsersByGroup(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des utilisateurs du groupe %q : %w", nom, err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d utilisateur(s) dans %s.", len(users), nom),
		Donnees: UtilisateursDeGroupe{Groupe: nom, Utilisateurs: users},
	}, nil
}

type UtilisateursDeGroupe struct {
	Groupe       string
	Utilisateurs []storage.DisplayUsersByGroup
}

func listerMachinesDuGroupe(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("group")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	clients, err := dbclients.Command_GET_ClientsByGroup(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des machines du groupe %q : %w", nom, err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d machine(s) dans %s.", len(clients), nom),
		Donnees: MachinesDeGroupe{Groupe: nom, Machines: clients},
	}, nil
}

type MachinesDeGroupe struct {
	Groupe   string
	Machines []storage.GetClientsByGroup
}
