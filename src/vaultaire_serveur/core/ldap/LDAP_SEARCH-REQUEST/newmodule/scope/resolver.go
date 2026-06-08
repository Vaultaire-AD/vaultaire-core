package scope

import (
	"database/sql"
	"fmt"
	"strings"
	"vaultaire/core/database"
	domainpkg "vaultaire/core/domain"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Resolve récupère tous les LDAPEntry (GroupEntry + UserEntry) pour un BaseDN et un scope donné
func Resolve(db *sql.DB, baseDN string, scope int, attributes []string, username string, baseObject string) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	var err error

	switch {
	case baseObject == "":
		entries = append(entries, candidate.NewRootDSE())
		logs.Write_Log("DEBUG", fmt.Sprintf("RootDSE struct: %+v", entries))
		return entries, nil
	case strings.EqualFold(baseObject, "cn=schema"), strings.EqualFold(baseObject, "cn=subschema"):
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

func loadGroupsAndUsers(db *sql.DB, domains []string, scope int, attributes []string, username string, baseObject string) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	seenUsers := make(map[string]struct{})
	seenGroups := make(map[string]struct{})
	seenOUs := make(map[string]struct{})

	// --- ÉTAPE 1 : PRÉ-CALCUL GLOBAL DU MEMBEROF ---
	// Cette map va stocker pour CHAQUE utilisateur son appartenance complète
	// Clé : username | Valeur : []string (liste des DNs de ses groupes)
	userMembershipMap := make(map[string][]string)

	for _, domain := range domains {
		var groupNames []string
		// On récupère TOUS les groupes du domaine pour avoir la vue d'ensemble
		groupNames, _ = domainpkg.GetGroupsUnderDomain(domain, db, false)

		if len(groupNames) > 0 {
			groupsData, _ := database.GetGroupsWithUsersByNames(db, groupNames)
			for _, g := range groupsData {
				// On utilise ToRootDN pour la cohérence avec les recherches Keycloak
				groupDN := fmt.Sprintf("cn=%s,ou=groups,%s", g.GroupName, ldaptools.ToRootDN(g.DomainName))

				for _, uname := range g.Users {
					userMembershipMap[uname] = append(userMembershipMap[uname], groupDN)
				}
			}
		}
	}

	// --- ÉTAPE 2 : GÉNÉRATION DES ENTRÉES (Logique actuelle modifiée) ---
	for _, domain := range domains {
		// [Garder ici ta logique de permission IsAuthorizedToSearch]

		// 1️⃣ Créer les OU (Inchangé)
		for _, ouName := range []string{"users", "groups"} {
			ouKey := fmt.Sprintf("%s|%s", ouName, domain)
			if _, exists := seenOUs[ouKey]; !exists {
				entries = append(entries, candidate.OUEntry{Name: ouName, BaseDN: domain})
				seenOUs[ouKey] = struct{}{}
			}
		}

		// Récupération des groupes pour ce domaine précis (Respect du scope)
		var groupNames []string
		if scope == 1 {
			groupNames, _ = domainpkg.GetGroupsDirectlyUnderDomainExact(domain, db, false)
		} else {
			groupNames, _ = domainpkg.GetGroupsUnderDomain(domain, db, false)
		}

		groups, _ := database.GetGroupsWithUsersByNames(db, groupNames)

		for _, g := range groups {
			// 2️⃣ Ajout du Groupe
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

			// 3️⃣ Ajout des Utilisateurs
			for _, uname := range g.Users {
				if _, exists := seenUsers[uname]; exists {
					continue // L'utilisateur a déjà été créé avec sa liste complète
				}

				userObj, err := database.GetUserByUsername(uname, db)
				if err != nil {
					continue
				}

				// 🔥 AMÉLIORATION : On pioche dans la map pré-calculée à l'étape 1
				// On a maintenant TOUS les groupes, peu importe le domaine
				fullMemberOf := userMembershipMap[uname]

				entries = append(entries, candidate.UserEntry{
					User:        userObj,
					BaseDN:      domain,       // Le domaine de découverte
					Groups:      fullMemberOf, // <--- Liste complète ICI
					DisplayName: userObj.Firstname + " " + userObj.Lastname,
					GivenName:   userObj.Firstname,
					Sn:          userObj.Lastname,
					Uid:         userObj.Username,
				})

				seenUsers[uname] = struct{}{}
			}
		}
	}

	// ... [Fin de fonction inchangée avec tes logs de debug] ...
	logs.Write_Log("DEBUG", fmt.Sprintf("loadGroupsAndUsers final entries: %d", len(entries)))
	if storage.Debug {
		for _, e := range entries {
			fmt.Printf("DN: %s, ObjectClasses: %v\n", e.DN(), e.ObjectClasses())
			PrintLDAPEntry(e, attributes)
		}
	}

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
		fmt.Printf("[FINAL-CHECK] Groupe %s envoie %d membres\n", entry.DN(), len(entry.GetAttribute("member")))
		for _, m := range entry.GetAttribute("member") {
			fmt.Printf("   -> Membre: %s\n", m)
		}
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
