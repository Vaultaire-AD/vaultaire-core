package permission

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbdomains "vaultaire/core/database/db_domains"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/domain"
	"vaultaire/core/domainname"
	"vaultaire/core/logs"
)

// CanUserConnectToDomain vérifie si un login au format "user@domain" (ou
// juste "user", sans domaine) a le droit de se connecter sous ce domaine.
//
// # Quels domaines sont valides pour une connexion
//
// Seuls les DOMAINES PRINCIPAUX des groupes du compte — les deux derniers
// labels. Un compte membre de groupes dans `infra.cloud.test.fr` et
// `rh.acme.lan` se connecte comme `alice@test.fr` ou `alice@acme.lan`, et sous
// rien d'autre : ni `alice@infra.cloud.test.fr`, ni `alice@autre.fr`, même si
// ce dernier existe dans l'annuaire.
//
// Avant, le domaine tapé n'était comparé qu'à l'annuaire ENTIER (« existe-t-il
// quelque part ? ») puis au droit `auth`. Un compte portant `auth` sur tout
// (l'amorçage, un administrateur) se connectait donc sous n'importe quel
// domaine existant, y compris ceux où il n'a aucun groupe — et la machine lui
// créait un compte local à ce nom.
//
// Plusieurs domaines principaux sont possibles : ils donnent des comptes
// locaux distincts sur une même machine (`alice@test.fr`, `alice@acme.lan`).
// C'est voulu.
//
// Le domaine doit être écrit en minuscules : `Alice@Test.FR` et
// `alice@test.fr` créeraient deux comptes locaux pour la même personne.
//
// # Le droit `auth`
//
// Vient ensuite le même contrôle que le bind LDAP : l'action legacy `auth`,
// résolue via PrePermissionCheck puis CheckPermissionsMultipleDomains (All /
// WithPropagation / NoPropagation / Deny). Il est évalué sur les domaines des
// groupes du compte SOUS le domaine principal demandé, et un seul suffit :
// un droit `1:infra.cloud.test.fr` ne propage que vers le bas, il ne couvre donc
// pas la chaîne `test.fr` elle-même — l'exiger sur `test.fr` refuserait ce
// compte, qui est pourtant autorisé là où il a ses groupes.
//
// Si le login ne contient pas de domaine (pas de "@"), seul un accès super
// admin (All, tous domaines) peut autoriser la connexion — comportement
// hérité de CheckPermissionsMultipleDomains quand la liste de domaines à
// vérifier est vide.
func CanUserConnectToDomain(login string) (bool, string) {
	username, targetDomain := domain.ExctractDomainFromUsername(login)

	// KILL SWITCH : couvre tout appelant de cette fonction. Redondant avec le
	// refus de GetGroupIDsForUser appelé plus bas, mais il produit un message
	// explicite au lieu d'une erreur de lecture de groupes.
	if IsRevoked(username) {
		logs.Write_LogCode("SECURITY", logs.CodeAuthLoginDenied,
			"Connexion refusée pour "+login+" : compte révoqué")
		return false, "compte révoqué"
	}

	var domainsToCheck []string
	if targetDomain != "" {
		sousDomaines, raison := domainesDuCompteSous(username, targetDomain, login)
		if raison != "" {
			return false, raison
		}
		domainsToCheck = sousDomaines
	}

	groupIDs, action, err := PrePermissionCheck(username, "auth")
	if err != nil {
		return false, err.Error()
	}

	if len(domainsToCheck) == 0 {
		return CheckPermissionsMultipleDomains(groupIDs, action, nil)
	}
	// Un seul domaine suffit — voir plus haut.
	var derniere string
	for _, d := range domainsToCheck {
		ok, raison := CheckPermissionsMultipleDomains(groupIDs, action, []string{d})
		if ok {
			return true, raison
		}
		derniere = raison
	}
	return false, derniere
}

// DomainesDeConnexion rend les domaines principaux sous lesquels un compte peut
// se connecter : ceux de ses groupes, réduits aux deux derniers labels.
func DomainesDeConnexion(username string) ([]string, error) {
	db := database.GetDatabase()
	userID, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return nil, err
	}
	domaines, err := dbdomains.GetDomainsForUser(db, userID)
	if err != nil {
		return nil, err
	}
	return domainname.DomainesPrincipaux(domaines), nil
}

// domainesDuCompteSous vérifie que cible est un domaine principal du compte et
// rend les domaines de ses groupes situés dessous. Une raison non vide est un
// refus.
func domainesDuCompteSous(username, cible, login string) ([]string, string) {
	if cible != domainname.NormaliserDomaine(cible) || domainname.ValiderDomaine(cible) != nil {
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied,
			"Connexion refusée pour "+login+" : domaine mal formé (minuscules, sans point final)")
		return nil, "domaine invalide : " + cible
	}

	db := database.GetDatabase()
	userID, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return nil, "utilisateur inconnu"
	}
	domaines, err := dbdomains.GetDomainsForUser(db, userID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"CanUserConnectToDomain: domaines de "+username+" illisibles : "+err.Error())
		return nil, "erreur vérification du domaine"
	}

	principaux := domainname.DomainesPrincipaux(domaines)
	membre := false
	for _, p := range principaux {
		if p == cible {
			membre = true
			break
		}
	}
	if !membre {
		// Le détail (les domaines valides) va au journal, pas au client : il
		// renseignerait qui essaie des domaines au hasard.
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, fmt.Sprintf(
			"Connexion refusée pour %s : %s n'est pas un domaine principal du compte (valides : %s)",
			login, cible, strings.Join(principaux, ", ")))
		return nil, "domaine non autorisé pour ce compte : " + cible
	}

	var sous []string
	for _, d := range domaines {
		if domainname.SousDomaineDe(d, cible) {
			sous = append(sous, d)
		}
	}
	return sous, ""
}
