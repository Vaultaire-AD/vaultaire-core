package scope

import (
	"database/sql"
	"fmt"
	"strings"
	dbldap "vaultaire/core/database/db_ldap"
	domainpkg "vaultaire/core/domain"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Resolve récupère tous les LDAPEntry (GroupEntry + UserEntry) pour un BaseDN et un scope donné
func Resolve(db *sql.DB, baseDN string, scope int, attributes []string, username string, baseObject string) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	var err error

	// Les constantes viennent de ldaptools, comme la détection : le
	// dispatcheur décide qu'un baseObject est spécial, ce résolveur décide ce
	// qu'il rend. Les deux doivent parler de la même liste.
	switch {
	case strings.TrimSpace(baseObject) == "":
		entries = append(entries, candidate.NewRootDSE())
		logs.Write_Log("DEBUG", fmt.Sprintf("RootDSE struct: %+v", entries))
		return entries, nil
	case strings.EqualFold(strings.TrimSpace(baseObject), ldaptools.SchemaDN),
		strings.EqualFold(strings.TrimSpace(baseObject), ldaptools.SubschemaDN):
		entries = append(entries, candidate.NewSchemaEntry())
		return entries, nil
	}

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: resolve baseDN=%s scope=%d baseObject=%s", baseDN, scope, baseObject))

	// JumpServer and similar clients search ou=users,dc=... with one-level scope but
	// expect users from all subdomains — use subtree group loading for user containers.
	loadScope := scope
	if isUserContainerSearch(baseObject) && scope == 1 {
		loadScope = 2
	}

	switch scope {
	case 0:
		if exact := resolveBaseScope(db, baseObject); exact != nil {
			return exact, nil
		}
		return nil, nil

	case 1:
		groupDomain := []string{baseDN}
		entries, err = loadGroupsAndUsers(db, groupDomain, loadScope, attributes, username, baseObject)
		if err != nil {
			return nil, err
		}
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: one-level loaded %d entries", len(entries)))
		// loadGroupsAndUsers est déjà scopé au domaine demandé ; ne pas re-filtrer par suffixe DN.
		return entries, nil

	case 2:
		groupDomains := []string{baseDN}
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: subtree scope base domains=%v", groupDomains))
		entries, err = loadGroupsAndUsers(db, groupDomains, loadScope, attributes, username, baseObject)
		if err != nil {
			return nil, err
		}
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: subtree loaded %d entries", len(entries)))
		// loadGroupsAndUsers est déjà scopé au domaine demandé ; ne pas re-filtrer par suffixe DN.
		return entries, nil

	default:
		return nil, fmt.Errorf("invalid scope: %d", scope)
	}
}

// loadGroupsAndUsers construit les entrées LDAP d'un ensemble de domaines.
//
// # Ce qui a changé, et pourquoi
//
// La version antérieure faisait trois choses coûteuses :
//
//  1. elle chargeait TOUS les groupes du domaine pour calculer les memberOf,
//     puis les rechargeait pour construire les entrées — deux fois le même
//     travail, sur les mêmes lignes ;
//  2. elle appelait GetUserByUsername une fois PAR utilisateur : 5 000 requêtes
//     SQL sur un annuaire de 5 000 comptes, pour une seule recherche ;
//  3. elle ignorait toutes les erreurs SQL avec « _ ». Une base injoignable
//     produisait une liste vide, donc une réponse LDAP « aucun résultat » avec
//     un code de SUCCÈS. Un client qui synchronise des comptes sur cette
//     réponse peut en supprimer.
//
// Désormais : un chargement des groupes, une lecture des utilisateurs en lot, et
// toute erreur remonte.
func loadGroupsAndUsers(db *sql.DB, domains []string, scope int, attributes []string, username string, baseObject string) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	seenUsers := make(map[string]struct{})
	seenGroups := make(map[string]struct{})
	seenOUs := make(map[string]struct{})

	// memberOf complet, tous domaines confondus.
	//
	// Il faut la vue d'ensemble : un utilisateur découvert dans un domaine peut
	// appartenir à des groupes d'un autre, et un client comme Keycloak s'attend à
	// les voir tous.
	userMembershipMap := make(map[string][]string)
	// Les groupes chargés une seule fois, réutilisés pour construire les entrées.
	groupesParDomaine := make(map[string][]ldapstorage.Group, len(domains))

	for _, domain := range domains {
		tousLesGroupes, err := domainpkg.GetGroupsUnderDomain(domain, db, false)
		if err != nil {
			return nil, fmt.Errorf("lecture des groupes du domaine %s : %w", domain, err)
		}
		groupsData, err := dbldap.GetGroupsWithUsersByNames(db, tousLesGroupes)
		if err != nil {
			return nil, fmt.Errorf("lecture des membres des groupes de %s : %w", domain, err)
		}
		for _, g := range groupsData {
			groupDN := fmt.Sprintf("cn=%s,ou=groups,%s", g.GroupName, ldaptools.ToRootDN(g.DomainName))
			for _, uname := range g.Users {
				userMembershipMap[uname] = append(userMembershipMap[uname], groupDN)
			}
		}

		// Les groupes du SCOPE demandé, qui peuvent être un sous-ensemble.
		//
		// Filtrés depuis ce qui vient d'être lu quand le scope est complet, pour
		// ne pas relancer la même requête.
		if scope == 1 {
			nomsDirects, err := domainpkg.GetGroupsDirectlyUnderDomainExact(domain, db, false)
			if err != nil {
				return nil, fmt.Errorf("lecture des groupes directs de %s : %w", domain, err)
			}
			retenus := make(map[string]struct{}, len(nomsDirects))
			for _, n := range nomsDirects {
				retenus[n] = struct{}{}
			}
			var filtrés []ldapstorage.Group
			for _, g := range groupsData {
				if _, ok := retenus[g.GroupName]; ok {
					filtrés = append(filtrés, g)
				}
			}
			groupesParDomaine[domain] = filtrés
		} else {
			groupesParDomaine[domain] = groupsData
		}
	}

	// Tous les utilisateurs à lire, en UNE fois.
	//
	// C'est ce qui remplace le N+1 : la liste est rassemblée d'abord, la lecture
	// vient ensuite. GetUsersByUsernames déduplique et découpe en lots.
	var àLire []string
	for _, domain := range domains {
		for _, g := range groupesParDomaine[domain] {
			àLire = append(àLire, g.Users...)
		}
	}
	utilisateurs, err := dbldap.GetUsersByUsernames(db, àLire)
	if err != nil {
		return nil, fmt.Errorf("lecture des utilisateurs : %w", err)
	}

	for _, domain := range domains {
		// Unités d'organisation du domaine.
		for _, ouName := range []string{"users", "groups"} {
			ouKey := fmt.Sprintf("%s|%s", ouName, domain)
			if _, exists := seenOUs[ouKey]; !exists {
				entries = append(entries, candidate.OUEntry{Name: ouName, BaseDN: domain})
				seenOUs[ouKey] = struct{}{}
			}
		}

		for _, g := range groupesParDomaine[domain] {
			groupKey := fmt.Sprintf("%s|%s", g.GroupName, g.DomainName)
			if _, exists := seenGroups[groupKey]; !exists {
				domainDN := ldaptools.ToRootDN(g.DomainName)
				memberDNs := make([]string, len(g.Users))
				for i, u := range g.Users {
					memberDNs[i] = fmt.Sprintf("uid=%s,ou=users,%s", u, domainDN)
				}
				entries = append(entries, candidate.GroupEntry{
					Name:    g.GroupName,
					BaseDN:  g.DomainName,
					Members: memberDNs,
				})
				seenGroups[groupKey] = struct{}{}
			}

			for _, uname := range g.Users {
				if _, exists := seenUsers[uname]; exists {
					continue
				}
				userObj, trouvé := utilisateurs[uname]
				if !trouvé {
					// Membre d'un groupe sans compte correspondant : incohérence de
					// données, pas une panne. On la journalise et on continue plutôt
					// que de faire échouer toute la recherche.
					logs.Write_Log("WARNING", "ldap: membre "+uname+" du groupe "+g.GroupName+" sans compte")
					continue
				}

				entries = append(entries, candidate.UserEntry{
					User:        userObj,
					BaseDN:      domain,
					Groups:      userMembershipMap[uname],
					DisplayName: userObj.Firstname + " " + userObj.Lastname,
					GivenName:   userObj.Firstname,
					Sn:          userObj.Lastname,
					Uid:         userObj.Username,
				})
				seenUsers[uname] = struct{}{}
			}
		}
	}

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: %d entrées construites", len(entries)))
	if storage.Debug {
		for _, e := range entries {
			logs.Write_Log("DEBUG", DumpLDAPEntry(e, attributes))
		}
	}
	return entries, nil
}

// DumpLDAPEntry rend une entrée sous forme lisible, pour le journal.
//
// Rend une CHAÎNE au lieu d'écrire sur la sortie standard : l'ancienne version
// écrivait directement, donc hors journalisation — sans horodatage, sans niveau,
// sans rotation — alors qu'elle affiche des données d'annuaire.
func DumpLDAPEntry(entry ldapinterface.LDAPEntry, requestedAttrs []string) string {
	var sb strings.Builder
	sb.WriteString("ldap entry " + entry.DN())

	classes := entry.ObjectClasses()
	isGroup := false
	for _, class := range classes {
		if strings.EqualFold(class, "groupOfNames") || strings.EqualFold(class, "group") {
			isGroup = true
			break
		}
	}

	var finalAttrs []string
	if isGroup {
		finalAttrs = ldaptools.MergeAttributes(requestedAttrs, ldaptools.MandatoryGroupAttrs)
	} else {
		finalAttrs = ldaptools.MergeAttributes(requestedAttrs, ldaptools.MandatoryUserAttrs)
	}
	for _, attr := range finalAttrs {
		sb.WriteString(fmt.Sprintf("\n  %-12s: %v", attr, entry.GetAttribute(attr)))
	}
	return sb.String()
}
