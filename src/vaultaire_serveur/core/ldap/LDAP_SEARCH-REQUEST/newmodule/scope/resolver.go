package scope

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	dbldap "vaultaire/core/database/db_ldap"
	domainpkg "vaultaire/core/domain"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// Resolve récupère tous les LDAPEntry (GroupEntry + UserEntry) pour un BaseDN et un scope donné
//
// `j` est le journal de l'opération en cours (TO-DO 145) : ce que le résolveur
// a à dire s'écrit sous l'identifiant de la connexion qui l'a demandé. Nil est
// accepté — un test, un appel hors connexion.
func Resolve(db *sql.DB, baseDN string, scope int, attributes []string, username string, baseObject string, j *ldapjournal.Operation) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	var err error

	// Les constantes viennent de ldaptools, comme la détection : le
	// dispatcheur décide qu'un baseObject est spécial, ce résolveur décide ce
	// qu'il rend. Les deux doivent parler de la même liste.
	switch {
	case strings.TrimSpace(baseObject) == "":
		entries = append(entries, candidate.NewRootDSE())
		return entries, nil
	case strings.EqualFold(strings.TrimSpace(baseObject), ldaptools.SchemaDN),
		strings.EqualFold(strings.TrimSpace(baseObject), ldaptools.SubschemaDN):
		entries = append(entries, candidate.NewSchemaEntry())
		return entries, nil
	}

	// UNE RECHERCHE `one` REND UN NIVEAU — sauf réglage contraire.
	//
	// La promotion en `sub` était silencieuse et déclenchée par le NOM du
	// conteneur : une recherche `one` sur `ou=users` rendait l'arborescence
	// entière, sous-domaines compris. Écrit pour JumpServer, qui cherche ainsi et
	// attend les sous-domaines ; subi par tous les autres, dont un administrateur
	// qui croyait restreindre un périmètre en configurant `scope=one`.
	//
	// Le réglage remplace l'exception : il est explicite, documenté, journalisé au
	// démarrage, et il vaut pour TOUTE recherche `one`, pas seulement celles dont
	// le conteneur s'appelle `users`. Un nom de conteneur n'a jamais été une bonne
	// raison de changer la portée d'une recherche.
	loadScope := porteeDeChargement(scope)
	if loadScope != scope {
		// Sur la ligne de l'opération, pas en déroulé : c'est ce qui explique
		// qu'une recherche « one » rende des sous-domaines, et on ne pense pas à
		// demander le déroulé pour le découvrir.
		j.Noter("élargie", "sub(ldap.onelevel_subtree)")
	}

	switch scope {
	case 0:
		if exact := resolveBaseScope(db, baseObject, j); exact != nil {
			return exact, nil
		}
		return nil, nil

	case 1:
		groupDomain := []string{baseDN}
		entries, err = loadGroupsAndUsers(db, groupDomain, loadScope, attributes, username, baseObject, j)
		if err != nil {
			return nil, err
		}
		// loadGroupsAndUsers est déjà scopé au domaine demandé ; ne pas re-filtrer par suffixe DN.
		return entries, nil

	case 2:
		groupDomains := []string{baseDN}
		entries, err = loadGroupsAndUsers(db, groupDomains, loadScope, attributes, username, baseObject, j)
		if err != nil {
			return nil, err
		}
		// loadGroupsAndUsers est déjà scopé au domaine demandé ; ne pas re-filtrer par suffixe DN.
		return entries, nil

	default:
		return nil, fmt.Errorf("invalid scope: %d", scope)
	}
}

// porteeDeChargement rend la portée à employer pour charger les candidats.
//
// La RÈGLE du point 127, isolée pour être éprouvée sans base : seule une
// recherche `one` peut être élargie, et seulement si le réglage le demande. Ni
// le nom du conteneur, ni la forme du DN, ni quoi que ce soit d'autre n'entre
// dans cette décision — c'était précisément le défaut.
func porteeDeChargement(scope int) int {
	if scope == 1 && ldapstorage.OneLevelSubtree {
		return 2
	}
	return scope
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
//
// « Un chargement des groupes » n'a été vrai qu'au point 131 :
// GetGroupsWithUsersByNames, appelée ici, faisait encore une requête par
// groupe. Elle lit maintenant par lots de 500 noms.
func loadGroupsAndUsers(db *sql.DB, domains []string, scope int, attributes []string, username string, baseObject string, j *ldapjournal.Operation) ([]ldapinterface.LDAPEntry, error) {
	entries := []ldapinterface.LDAPEntry{}
	seenUsers := make(map[string]struct{})
	seenGroups := make(map[string]struct{})
	seenOUs := make(map[string]struct{})

	// memberOf, pour tous les groupes chargés — le domaine demandé ET ses
	// sous-domaines.
	//
	// Chaque groupe y entre avec SON domaine (TO-DO 132) : c'est ce qui permet
	// au contrôle d'accès de retirer ensuite, compte par compte, ceux que
	// l'appelant n'a pas le droit de lire. Le résolveur, lui, ne trie rien : il
	// ne connaît pas les droits, et ne doit pas les connaître.
	userMembershipMap := make(map[string][]candidate.Appartenance)
	// Les DOMAINES où vit chaque compte, c'est-à-dire ceux des groupes par
	// lesquels il a été trouvé. C'est ce qui sert au contrôle d'accès.
	//
	// Il ne peut pas être remplacé par `domain` : cette variable de boucle porte
	// le domaine DEMANDÉ par le client, et la première version du point 120 s'en
	// servait — ce qui autorisait tout compte par construction, puisque le filtre
	// ne voyait jamais que le domaine qui venait d'être autorisé.
	//
	// Il ne peut pas non plus être déduit du DN : `ToRootDN` ne garde que les deux
	// derniers labels, si bien qu'un compte de `admin.enov.local` et un compte de
	// `enov.local` ont exactement le même DN.
	rattachements := make(map[string]map[string]struct{})
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
				userMembershipMap[uname] = append(userMembershipMap[uname],
					candidate.Appartenance{DN: groupDN, Domaine: g.DomainName})
				if rattachements[uname] == nil {
					rattachements[uname] = make(map[string]struct{}, 2)
				}
				rattachements[uname][g.DomainName] = struct{}{}
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
					Name:        g.GroupName,
					BaseDN:      g.DomainName,
					Members:     memberDNs,
					Created_at:  g.Created_at,
					Modified_at: g.Modified_at,
					EntryUUID:   g.EntryUUID,
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
					j.Ecrire("WARNING", logs.CodeNone, "membre "+uname+" du groupe "+g.GroupName+" sans compte")
					continue
				}

				entries = append(entries, candidate.UserEntry{
					User: userObj,
					// BaseDN compose le DN, Rattachements décide des droits. Les deux
					// diffèrent, et c'est le fond du point 120 : le DN d'un compte de
					// sous-domaine est identique à celui d'un compte du domaine parent.
					BaseDN:        domain,
					Rattachements: domainesDe(rattachements[uname]),
					Groups:        userMembershipMap[uname],
					DisplayName:   userObj.Firstname + " " + userObj.Lastname,
					GivenName:     userObj.Firstname,
					Sn:            userObj.Lastname,
					Uid:           userObj.Username,
				})
				seenUsers[uname] = struct{}{}
			}
		}
	}

	// Le vidage détaillé des entrées a été déplacé dans le gestionnaire, APRÈS le
	// filtre d'autorisation.
	//
	// Il avait lieu ici, donc avant : le journal DEBUG portait le contenu des
	// entrées que le compte n'a PAS le droit de lire — cn, mail, memberOf, uid des
	// sous-domaines — écrit sur disque. Corriger la fuite vers le client en la
	// laissant vers le journal n'aurait pas été une correction.
	return entries, nil
}

// domainesDe rend un ensemble de domaines sous forme de liste.
//
// Trié, pour que deux exécutions de la même recherche produisent la même chose :
// une liste dont l'ordre dépend du parcours d'une table de hachage rend les
// journaux incomparables et les tests intermittents.
func domainesDe(ensemble map[string]struct{}) []string {
	if len(ensemble) == 0 {
		return nil
	}
	liste := make([]string, 0, len(ensemble))
	for d := range ensemble {
		liste = append(liste, d)
	}
	sort.Strings(liste)
	return liste
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
