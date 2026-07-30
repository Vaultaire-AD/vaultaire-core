package gpomanager

import (
	"database/sql"
	"fmt"
	"sort"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// Résolution des politiques effectives applicables à un client ou à un couple
// client/utilisateur.
//
// La séparation des deux résolutions est structurelle :
//   - la politique machine dépend des groupes du CLIENT, elle vaut pour la
//     machine quel que soit l'utilisateur connecté ;
//   - la politique user dépend des groupes PARTAGÉS entre l'utilisateur et la
//     machine, et non de tous les groupes de l'utilisateur.
//
// Tous les modules de sécurité (SSH, sudo, sysctl, paquets, services) étant
// machine-only dans le catalogue, aucune politique user ne peut les surcharger.

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
	logs.Write_LogCode("DEBUG", logs.CodeGPOResolve, fmt.Sprintf(
		"gpo: client %s (id %d) appartient à %d groupe(s)", clientSoftwareID, clientID, len(groupIDs)))

	if len(groupIDs) == 0 {
		return empty, nil
	}

	policies, err := dbgpo.GetPoliciesForGroupIDs(db, groupIDs, gpo.ScopeMachine)
	if err != nil {
		return gpo.Policy{}, err
	}
	logs.Write_LogCode("DEBUG", logs.CodeGPOResolve, fmt.Sprintf(
		"gpo: %d GPO machine activée(s) trouvée(s) pour le client %s", len(policies), clientSoftwareID))

	if len(policies) == 0 {
		return empty, nil
	}
	return gpo.BuildPolicyForDelivery(gpo.ScopeMachine, policies)
}

// resolveUserPolicy fusionne les GPO user des groupes partagés entre
// l'utilisateur et la machine.
//
// L'intersection est la règle documentée du protocole, et elle a une raison
// précise : sans elle, un utilisateur emporterait la configuration d'un groupe
// sur une machine qui n'en fait pas partie. Autrement dit l'utilisateur
// choisirait une partie de la configuration d'une machine à laquelle il ne fait
// que se connecter.
func resolveUserPolicy(db *sql.DB, username, clientSoftwareID string) (gpo.Policy, error) {
	empty := gpo.Policy{Name: "effective_user", Scope: gpo.ScopeUser, Enabled: true}

	if username == "" {
		return gpo.Policy{}, fmt.Errorf("utilisateur cible non fourni")
	}

	userGroupIDs, err := database.Command_GET_UserGroupIDs(db, username)
	if err != nil {
		return gpo.Policy{}, fmt.Errorf("groupes de l'utilisateur %s illisibles : %v", username, err)
	}
	clientID, err := database.Get_ClientID_By_ComputerID(db, clientSoftwareID)
	if err != nil {
		return gpo.Policy{}, fmt.Errorf("client %s introuvable : %v", clientSoftwareID, err)
	}
	clientGroupIDs, err := database.Command_GET_GroupIDsFromClientID(db, clientID)
	if err != nil {
		return gpo.Policy{}, fmt.Errorf("groupes du client %s illisibles : %v", clientSoftwareID, err)
	}

	shared := intersectGroupIDs(userGroupIDs, clientGroupIDs)
	logs.Write_LogCode("DEBUG", logs.CodeGPOResolve, fmt.Sprintf(
		"gpo: intersection pour %s sur %s — utilisateur:%v machine:%v partagés:%v",
		username, clientSoftwareID, userGroupIDs, clientGroupIDs, shared))

	if len(shared) == 0 {
		logs.Write_LogCode("DEBUG", logs.CodeGPOResolve, fmt.Sprintf(
			"gpo: aucun groupe commun entre %s et %s, aucune GPO user applicable", username, clientSoftwareID))
		return empty, nil
	}

	policies, err := dbgpo.GetPoliciesForGroupIDs(db, shared, gpo.ScopeUser)
	if err != nil {
		return gpo.Policy{}, err
	}
	logs.Write_LogCode("DEBUG", logs.CodeGPOResolve, fmt.Sprintf(
		"gpo: %d GPO user activée(s) trouvée(s) pour %s sur %s", len(policies), username, clientSoftwareID))

	if len(policies) == 0 {
		return empty, nil
	}
	return gpo.BuildPolicyForDelivery(gpo.ScopeUser, policies)
}

// intersectGroupIDs retourne les identifiants présents dans les deux listes,
// triés et dédupliqués pour que la résolution soit déterministe.
func intersectGroupIDs(a, b []int) []int {
	inB := make(map[int]bool, len(b))
	for _, id := range b {
		inB[id] = true
	}
	seen := map[int]bool{}
	var out []int
	for _, id := range a {
		if inB[id] && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Ints(out)
	return out
}

// HasSharedGroup indique si l'utilisateur et la machine partagent un groupe.
// Utilisé pour distinguer « aucun groupe commun » d'une politique simplement vide.
func HasSharedGroup(db *sql.DB, username, clientSoftwareID string) bool {
	userGroupIDs, err := database.Command_GET_UserGroupIDs(db, username)
	if err != nil {
		return false
	}
	clientID, err := database.Get_ClientID_By_ComputerID(db, clientSoftwareID)
	if err != nil {
		return false
	}
	clientGroupIDs, err := database.Command_GET_GroupIDsFromClientID(db, clientID)
	if err != nil {
		return false
	}
	return len(intersectGroupIDs(userGroupIDs, clientGroupIDs)) > 0
}
