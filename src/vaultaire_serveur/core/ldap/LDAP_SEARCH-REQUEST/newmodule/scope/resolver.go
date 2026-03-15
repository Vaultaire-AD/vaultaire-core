package scope

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	"vaultaire/core/domain"
	domainpkg "vaultaire/core/domain"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/security"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// Resolve récupère tous les LDAPEntry (GroupEntry + UserEntry) pour un BaseDN et un scope donné
func Resolve(db *sql.DB, baseDN string, scope int, attributes []string, username string, baseObject string) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	if baseDN == "" || baseObject == "cn=schema" {
		entries, err := loadGroupsAndUsers(db, []string{}, scope, attributes, username, baseObject) // On appelle avec une liste vide pour indiquer que c'est une requête RootDSE
		if err != nil {
			return nil, err
		}
		logs.Write_Log("DEBUG", fmt.Sprintf("RootDSE struct: %+v", entries))
		return entries, nil // La résolution du RootDSE est gérée à part
	}
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: resolve baseDN=%s scope=%d", baseDN, scope))
	switch scope {
	case 0: // base → juste le domaine lui-même
		entries = append(entries, candidate.DomainEntry{DNName: baseDN})

	case 1: // one-level → groupes directs + leurs utilisateurs
		groupDomain, err := domainpkg.GetGroupsDirectlyUnderDomainExact(baseDN, db, true)
		if err != nil {
			return nil, err
		}
		entries, err = loadGroupsAndUsers(db, groupDomain, 1, attributes, username, baseObject)
		if err != nil {
			return nil, err
		}

	case 2: // subtree → tous les groupes + tous les utilisateurs
		groupDomains, err := domain.GetGroupsDirectlyUnderDomain(baseDN, db, true)
		if err != nil {
			return nil, err
		}
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: subtree scope group domains=%v", groupDomains))
		entries, err = loadGroupsAndUsers(db, groupDomains, 2, attributes, username, baseObject)
		if err != nil {
			return nil, err
		}
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: subtree loaded %d entries", len(entries)))

	default:
		return nil, fmt.Errorf("invalid scope: %d", scope)
	}

	return entries, nil
}

// loadGroupsAndUsers récupère pour chaque domaine/groupe les GroupEntry et les UserEntry correspondants
// avec gestion du scope pour éviter de retourner tous les groupes sous-jacents par défaut.
// Cette version enrichit les attributs LDAP pour compatibilité Nextcloud et autres clients.
func loadGroupsAndUsers(db *sql.DB, domains []string, scope int, attributes []string, username string, baseObject string) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	seenUsers := make(map[string]struct{})
	seenGroups := make(map[string]struct{}) // clé = "groupName|domain"
	seenOUs := make(map[string]struct{})    // clé = "ouName|domain" pour éviter doublons

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: resolve baseDN='%v' scope=%d", domains, scope))

	// CAS 1 : SCHEMA
	if baseObject == "cn=schema" || baseObject == "cn=subschema" {
		schema := candidate.NewSchemaEntry()

		entries = append(entries, schema)
		return entries, nil
	}
	// ✅ CAS 2 : Gestion explicite de la requête RootDSE
	if len(domains) == 0 {
		root := candidate.NewRootDSE()
		// Crée la slice requise et y ajoute l'objet
		entries = append(entries, root) // RootDSEEntry implémente LDAPEntry, donc on peut l'ajouter directement{
		return entries, nil
	}

	for _, domain := range domains {
		// 2️⃣ Check permission par domaine
		if !security.IsAuthorizedToSearch(username, domain) {
			logs.Write_Log("DEBUG", fmt.Sprintf("Search denied on domain %s for %s", domain, username))
			continue
		}

		// 1️⃣ Créer les OU fictives pour ce domaine si elles n'existent pas déjà
		for _, ouName := range []string{"users", "groups"} {
			ouKey := fmt.Sprintf("%s|%s", ouName, domain)
			if _, exists := seenOUs[ouKey]; !exists {
				entries = append(entries, candidate.OUEntry{
					Name:   ouName,
					BaseDN: domain,
				})
				seenOUs[ouKey] = struct{}{}
			}
		}

		var groupNames []string
		var err error
		// selon le scope, on ne prend que les groupes directs ou tous les groupes sous le domaine
		if scope == 1 {
			groupNames, err = domainpkg.GetGroupsDirectlyUnderDomainExact(domain, db, false)
		} else { // scope 2 (subtree)
			groupNames, err = domainpkg.GetGroupsUnderDomain(domain, db, false)
		}
		if err != nil {
			return nil, err
		}

		if len(groupNames) == 0 {
			continue
		}

		groups, err := database.GetGroupsWithUsersByNames(db, groupNames)
		if err != nil {
			return nil, err
		}

		for _, g := range groups {
			groupKey := fmt.Sprintf("%s|%s", g.GroupName, g.DomainName)
			if _, exists := seenGroups[groupKey]; exists {
				continue
			}
			seenGroups[groupKey] = struct{}{}

			domainDN := ldaptools.DomainToDN(g.DomainName)
			memberDNs := make([]string, len(g.Users))
			for i, u := range g.Users {
				memberDNs[i] = fmt.Sprintf(
					"uid=%s,ou=users,%s",
					u,
					domainDN,
				)
			}

			entries = append(entries, candidate.GroupEntry{
				Name:    g.GroupName,
				BaseDN:  g.DomainName,
				Members: memberDNs,
			})

			// UserEntry
			for _, uname := range g.Users {
				if _, exists := seenUsers[uname]; exists {
					continue
				}

				userObj, err := database.GetUserByUsername(uname, db)
				if err != nil {
					logs.Write_Log("WARNING", fmt.Sprintf("User %s not found", uname))
					continue
				}

				// Calculer memberOf automatiquement
				memberOf := []string{}
				for _, grp := range groups {
					domainDN := ldaptools.DomainToDN(grp.DomainName)

					for _, u := range grp.Users {
						if u == uname {
							memberOf = append(
								memberOf,
								fmt.Sprintf(
									"cn=%s,ou=groups,%s",
									grp.GroupName,
									domainDN,
								),
							)
						}
					}
				}

				entries = append(entries, candidate.UserEntry{
					User: ldapstorage.User{
						ID:          userObj.ID,
						Username:    userObj.Username,
						GroupDomain: userObj.GroupDomain,
						Firstname:   userObj.Firstname,
						Lastname:    userObj.Lastname,
						Email:       userObj.Email,
						Created_at:  userObj.Created_at,
					},
					BaseDN:      g.DomainName,
					Groups:      memberOf,
					DisplayName: userObj.Firstname + " " + userObj.Lastname,
					GivenName:   userObj.Firstname,
					Sn:          userObj.Lastname,
					Uid:         userObj.Username,
				})

				seenUsers[uname] = struct{}{}
			}
		}
	}

	logs.Write_Log("DEBUG", fmt.Sprintf("loadGroupsAndUsers final entries: %d", len(entries)))

	// for _, e := range entries {
	// 	fmt.Printf("DN: %s, ObjectClasses: %v\n", e.DN(), e.ObjectClasses())
	// 	PrintLDAPEntry(e, attributes)
	// }

	return entries, nil
}

// PrintLDAPEntry affiche les informations complètes d'une entrée LDAP
func PrintLDAPEntry(entry ldapinterface.LDAPEntry, requestedAttrs []string) {
	fmt.Println("=== LDAP Entry ===")
	fmt.Println("DN         :", entry.DN())

	// ObjectClasses
	classes := entry.ObjectClasses()
	fmt.Printf("ObjectClass: %v\n", classes)
	// 1. Détermine le type d'objet
	isGroup := false
	for _, class := range classes {
		// Le FortiGate cherche souvent "groupOfNames" ou "group"
		if strings.ToLower(class) == "groupofnames" || strings.ToLower(class) == "group" {
			isGroup = true
			break
		}
	}

	// 2. Fusionne les attributs requis
	// C'est ici que tu dois utiliser tes constantes (ex: MandatoryGroupAttrs)
	var finalAttrs []string
	if isGroup {
		finalAttrs = ldaptools.MergeAttributes(requestedAttrs, ldaptools.MandatoryGroupAttrs)
	} else {
		finalAttrs = ldaptools.MergeAttributes(requestedAttrs, ldaptools.MandatoryUserAttrs)
	}
	// afficher tous les attributs
	for _, attr := range finalAttrs {
		vals := entry.GetAttribute(attr)
		if len(vals) > 0 {
			fmt.Printf("%-12s: %v\n", attr, vals)
		} else {
			fmt.Printf("%-12s: []\n", attr)
		}
	}

	fmt.Println("=================")
}
