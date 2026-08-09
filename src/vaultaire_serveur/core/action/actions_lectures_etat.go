package action

import (
	"fmt"

	"vaultaire/core/database"
	dbsessions "vaultaire/core/database/db_sessions"
	"vaultaire/core/storage"
)

// Actions de LECTURE — état des sessions.
//
// `status -u` et `status -c` répondent à une question différente des lectures
// d'annuaire : non pas « qui existe » mais « qui est connecté en ce moment ».
//
// # Une clé RBAC distincte, et c'est voulu
//
// `read:status:user` et `read:status:client` ne se confondent pas avec
// `read:get:*`. Savoir qu'un compte existe et savoir qu'il est ouvert sur une
// machine à cet instant ne se délèguent pas de la même façon : la seconde
// information sert à surveiller des personnes.
//
// # Le défaut que le portage corrige
//
// `status -u <compte>` et `status -c <machine>` contrôlaient bien sur les
// domaines de la cible. Mais `status -u` SANS argument — la liste de tous les
// connectés — exigeait le droit sur « * », donc global. Un délégué de paris se
// voyait refuser la liste entière au lieu d'obtenir sa part, exactement comme
// pour `get -c` et `get -p`.

// EnregistrerActionsLectureEtat ajoute les lectures d'état de session.
func EnregistrerActionsLectureEtat(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:             "session.list_users",
		CleRBAC:         "read:status:user",
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          filtrerSessionsUtilisateur,
		Resume:          "liste les utilisateurs connectés",
		Executer:        listerSessionsUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:             "session.get_user",
		CleRBAC:         "read:status:user",
		Portee:          PorteeUtilisateur,
		UnDomaineSuffit: true,
		Resume:          "état de connexion d'un utilisateur",
		Executer:        lireSessionUtilisateur,
	})

	r.MustEnregistrer(Definition{
		Nom:             "session.list_users_by_group",
		CleRBAC:         "read:status:user",
		Portee:          PorteeGroupe,
		UnDomaineSuffit: true,
		Filtre:          filtrerSessionsUtilisateur,
		Resume:          "utilisateurs connectés d'un groupe",
		Executer:        listerSessionsUtilisateurParGroupe,
	})

	r.MustEnregistrer(Definition{
		Nom:             "session.list_clients",
		CleRBAC:         "read:status:client",
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          filtrerSessionsClient,
		Resume:          "liste les machines connectées",
		Executer:        listerSessionsClient,
	})

	r.MustEnregistrer(Definition{
		Nom:             "session.list_clients_by_group",
		CleRBAC:         "read:status:client",
		Portee:          PorteeGroupe,
		UnDomaineSuffit: true,
		Filtre:          filtrerSessionsClient,
		Resume:          "machines connectées d'un groupe",
		Executer:        listerSessionsClientParGroupe,
	})

	r.MustEnregistrer(Definition{
		Nom:     "session.list_clients_by_type",
		CleRBAC: "read:status:client",
		// Portée globale : un type de logiciel — « vaultaire_web », un proxy —
		// n'appartient à aucun domaine. Le filtre réduit ensuite aux machines
		// visibles.
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		Filtre:          filtrerSessionsClient,
		Resume:          "machines connectées d'un type de logiciel",
		Executer:        listerSessionsClientParType,
	})
}

// --- filtres -----------------------------------------------------------------

func filtrerSessionsUtilisateur(donnees any, perim Perimetre) (any, int) {
	sessions, ok := donnees.([]storage.UserConnected)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.UserConnected, 0, len(sessions))
	for _, s := range sessions {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteUtilisateur, s.Username)) {
			garde = append(garde, s)
		}
	}
	return garde, len(sessions) - len(garde)
}

func filtrerSessionsClient(donnees any, perim Perimetre) (any, int) {
	sessions, ok := donnees.([]storage.ClientConnected)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.ClientConnected, 0, len(sessions))
	for _, s := range sessions {
		if perim.AutoriseUnDes(perim.DomainesDe(EntiteClient, s.ComputeurID)) {
			garde = append(garde, s)
		}
	}
	return garde, len(sessions) - len(garde)
}

// --- utilisateurs ------------------------------------------------------------

func listerSessionsUtilisateur(_ Appelant, _ Params) (Resultat, error) {
	sessions, err := dbsessions.Command_STATUS_GetConnectedUsers(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des sessions utilisateur : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d utilisateur(s) connecté(s).", len(sessions)),
		Donnees: sessions,
	}, nil
}

func lireSessionUtilisateur(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("username")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom d'utilisateur requis")
	}
	sessions, err := dbsessions.Command_STATUS_GetConnectedUser(database.GetDatabase(), nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des sessions de %q : %w", nom, err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d session(s) pour %s.", len(sessions), nom),
		Donnees: sessions,
	}, nil
}

func listerSessionsUtilisateurParGroupe(_ Appelant, p Params) (Resultat, error) {
	groupe := p.Get("group")
	if groupe == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	sessions, err := dbsessions.Command_STATUS_GetUsersByGroup(database.GetDatabase(), groupe)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des sessions du groupe %q : %w", groupe, err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d utilisateur(s) connecté(s) dans %s.", len(sessions), groupe),
		Donnees: sessions,
	}, nil
}

// --- machines ----------------------------------------------------------------

func listerSessionsClient(_ Appelant, _ Params) (Resultat, error) {
	sessions, err := dbsessions.Command_STATUS_GetClientsConnected(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des sessions machine : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d machine(s) connectée(s).", len(sessions)),
		Donnees: sessions,
	}, nil
}

func listerSessionsClientParGroupe(_ Appelant, p Params) (Resultat, error) {
	groupe := p.Get("group")
	if groupe == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	sessions, err := dbsessions.Command_STATUS_GetClientsConnectedByGroup(database.GetDatabase(), groupe)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des machines du groupe %q : %w", groupe, err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d machine(s) connectée(s) dans %s.", len(sessions), groupe),
		Donnees: sessions,
	}, nil
}

func listerSessionsClientParType(_ Appelant, p Params) (Resultat, error) {
	typeLogiciel := p.Get("client_type")
	if typeLogiciel == "" {
		return Resultat{}, fmt.Errorf("type de logiciel requis")
	}
	sessions, err := dbsessions.Command_STATUS_GetClientsConnectedByLogicielType(
		database.GetDatabase(), typeLogiciel)
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des machines de type %q : %w", typeLogiciel, err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d machine(s) connectée(s) de type %s.", len(sessions), typeLogiciel),
		Donnees: sessions,
	}, nil
}
