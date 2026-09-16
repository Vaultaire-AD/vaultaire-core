package webserveur

import (
	"vaultaire/core/action"
)

// Périmètre de visibilité — adaptateur pour la recherche globale.
//
// # Ce fichier ne décide plus rien
//
// La logique de filtrage vivait ICI et nulle part ailleurs : les pages
// d'administration réduisaient leurs listes au périmètre de l'appelant tandis
// que la ligne de commande ne filtrait rien — `get -u` rendait l'annuaire
// entier dès qu'on avait `read:get:user` quelque part.
//
// Le contrôle des ÉCRITURES était pourtant identique des deux côtés. Seule la
// visibilité divergeait, et dans le sens le plus gênant : la divulgation que le
// modèle de délégation existe précisément pour empêcher restait ouverte par la
// porte de derrière.
//
// Elle est désormais dans core/action/perimetre.go, déclarée par chaque action
// de liste et appliquée par l'exécuteur. Les cinq fonctions qui vivaient ici —
// filterUsers, filterGroups, filterClients, filterUserPermissions,
// logScopeFiltering — ont disparu avec leurs appelants.
//
// Ce qui reste est l'enveloppe employée par la RECHERCHE GLOBALE, qui parcourt
// quatre genres d'entités dans une même réponse et ne se ramène donc pas à une
// action de liste. Elle ne réimplémente rien : elle transmet.
type domainScope struct {
	perim action.Perimetre
}

// newDomainScope calcule le périmètre d'une clé RBAC pour un jeu de groupes.
func newDomainScope(groupIDs []int, cleRBAC string) *domainScope {
	return &domainScope{perim: action.PerimetreVaultaire{}.Perimetre(groupIDs, cleRBAC)}
}

func (s *domainScope) allowsAny(domaines []string) bool { return s.perim.AutoriseUnDes(domaines) }

func (s *domainScope) domainsOfUser(u string) []string {
	return s.perim.DomainesDe(action.EntiteUtilisateur, u)
}

func (s *domainScope) domainsOfClient(c string) []string {
	return s.perim.DomainesDe(action.EntiteClient, c)
}

func (s *domainScope) domainsOfPermission(n string) []string {
	return s.perim.DomainesDe(action.EntitePermission, n)
}
