package scope

import (
	domainpkg "DUCKY/serveur/domain"
	candidate "DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	"DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/ldap_types"
	"DUCKY/serveur/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	ldapsessionmanager "DUCKY/serveur/ldap/LDAP_SESSION-Manager"
	"DUCKY/serveur/logs"
	"database/sql"
	"fmt"
	"net"
)

func HandleGlobalUserDisplayNameSearch(
	conn net.Conn,
	messageID int,
	session *ldapsessionmanager.LDAPSession,
	db *sql.DB,
	requestedAttrs []string,
) {

	// Session invalide → réponse vide (pas de LDAP failed)
	if session == nil || session.Username == "" {
		logs.Write_Log("WARN", "Global search refused: invalid session")
		response.SendLDAPSearchResultDone(conn, messageID)
		return
	}

	logs.Write_Log(
		"DEBUG",
		fmt.Sprintf("Global displayName search requested by %s", session.Username),
	)

	// 1️⃣ Tous les domaines
	domains, err := domainpkg.GetAllGroupDomains(db, true)
	if err != nil {
		logs.Write_Log("ERROR", "Failed to load domains: "+err.Error())
		response.SendLDAPSearchResultDone(conn, messageID)
		return
	}

	seenUsers := make(map[string]struct{})

	for _, domain := range domains {

		// 3️⃣ Groupes + users du domaine
		entries, err := loadGroupsAndUsers(db, []string{domain}, 2, requestedAttrs, session.Username)
		if err != nil {
			logs.Write_Log(
				"ERROR",
				fmt.Sprintf("Failed to load users for domain %s: %v", domain, err),
			)
			continue
		}

		for _, e := range entries {
			user, ok := e.(candidate.UserEntry)
			if !ok {
				continue
			}

			// Anti-doublon global
			if _, exists := seenUsers[user.User.Username]; exists {
				continue
			}
			seenUsers[user.User.Username] = struct{}{}

			// 4️⃣ Construction des attributs LDAP
			var attrs []ldap_types.PartialAttribute
			added := make(map[string]bool)

			// --- Attributs obligatoires pour Nextcloud ---
			mandatoryAttrs := map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"uid":         {user.User.Username},
				"cn":          {user.User.Username},
			}

			for attr, values := range mandatoryAttrs {
				attrs = append(attrs, ldap_types.PartialAttribute{
					Type: attr,
					Vals: values,
				})
				added[attr] = true
			}

			// --- Attributs demandés par le client ---
			for _, attr := range requestedAttrs {
				if added[attr] {
					continue
				}

				if values := user.GetAttribute(attr); len(values) > 0 {
					attrs = append(attrs, ldap_types.PartialAttribute{
						Type: attr,
						Vals: values,
					})
					added[attr] = true
				}
			}

			entry := ldap_types.SearchResultEntry{
				ObjectName: user.DN(),
				Attributes: attrs,
			}

			// 🔹 Nouveau log détaillé
			logs.Write_Log(
				"DEBUG",
				fmt.Sprintf(
					"Sending LDAP entry to client:\nDN=%s\nAttributes:\n%s",
					entry.ObjectName,
					formatAttrsForLog(attrs),
				),
			)
			// ✅ BON APPEL
			_ = response.SendLDAPSearchResultEntry(
				conn,
				messageID,
				entry,
			)
		}
	}

	logs.Write_Log(
		"DEBUG",
		fmt.Sprintf("Global displayName search done (%d users)", len(seenUsers)),
	)

	response.SendLDAPSearchResultDone(conn, messageID)
}

func formatAttrsForLog(attrs []ldap_types.PartialAttribute) string {
	out := ""
	for _, a := range attrs {
		out += fmt.Sprintf(" - %s: %v\n", a.Type, a.Vals)
	}
	return out
}
