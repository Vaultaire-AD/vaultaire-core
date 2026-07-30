package gpomanager

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
)

// Get_GPO_forClient calcule les deux politiques effectives applicables lors
// d'une authentification : celle de la machine et celle de l'utilisateur.
//
// La séparation des deux résolutions est structurelle et non cosmétique :
//   - la politique machine dépend des groupes du CLIENT (elle vaut pour la
//     machine, quel que soit l'utilisateur connecté) ;
//   - la politique user dépend des groupes de l'UTILISATEUR (elle le suit sur
//     toutes les machines du domaine où il peut se connecter).
//
// Chacune est fusionnée séparément, et la machine reste la baseline : puisque
// tous les modules de sécurité (SSH, sudo, sysctl, paquets, services) sont
// machine-only dans le catalogue, aucune politique user ne peut les surcharger.
func Get_GPO_forClient(username string, clientSoftwareID string) (machine gpo.Policy, user gpo.Policy, err error) {
	db := database.GetDatabase()
	if db == nil {
		return gpo.Policy{}, gpo.Policy{}, fmt.Errorf("gpo: connexion base indisponible")
	}

	machine, err = resolveMachinePolicy(db, clientSoftwareID)
	if err != nil {
		return gpo.Policy{}, gpo.Policy{}, err
	}
	user, err = resolveUserPolicy(db, username)
	if err != nil {
		return gpo.Policy{}, gpo.Policy{}, err
	}
	return machine, user, nil
}

// resolveMachinePolicy fusionne les GPO machine liées aux groupes du client.
func resolveMachinePolicy(db *sql.DB, clientSoftwareID string) (gpo.Policy, error) {
	empty := gpo.Policy{Name: "effective_machine", Scope: gpo.ScopeMachine, Enabled: true}

	clientID, err := database.Get_ClientID_By_ComputerID(db, clientSoftwareID)
	if err != nil {
		return gpo.Policy{}, fmt.Errorf("client %s introuvable : %v", clientSoftwareID, err)
	}
	groupIDs, err := database.Command_GET_GroupIDsFromClientID(db, clientID)
	if err != nil {
		return gpo.Policy{}, fmt.Errorf("groupes du client %s illisibles : %v", clientSoftwareID, err)
	}
	if len(groupIDs) == 0 {
		return empty, nil
	}

	policies, err := dbgpo.GetPoliciesForGroupIDs(db, groupIDs, gpo.ScopeMachine)
	if err != nil {
		return gpo.Policy{}, err
	}
	if len(policies) == 0 {
		return empty, nil
	}
	return gpo.BuildPolicyForDelivery(gpo.ScopeMachine, policies)
}

// resolveUserPolicy fusionne les GPO user liées aux groupes de l'utilisateur.
func resolveUserPolicy(db *sql.DB, username string) (gpo.Policy, error) {
	empty := gpo.Policy{Name: "effective_user", Scope: gpo.ScopeUser, Enabled: true}

	if username == "" {
		return empty, nil
	}
	groupIDs, err := database.Command_GET_UserGroupIDs(db, username)
	if err != nil {
		return gpo.Policy{}, fmt.Errorf("groupes de l'utilisateur %s illisibles : %v", username, err)
	}
	if len(groupIDs) == 0 {
		return empty, nil
	}

	policies, err := dbgpo.GetPoliciesForGroupIDs(db, groupIDs, gpo.ScopeUser)
	if err != nil {
		return gpo.Policy{}, err
	}
	if len(policies) == 0 {
		return empty, nil
	}
	return gpo.BuildPolicyForDelivery(gpo.ScopeUser, policies)
}
