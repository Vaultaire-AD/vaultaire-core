package newmodule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/pagination"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/response"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
)

// La pagination des recherches — RFC 2696, point 130.
//
// Ce fichier porte ce que le GESTIONNAIRE décide : quand une recherche est
// paginée, de quelle taille, sous quelle borne, et ce qu'il répond. Ce qui est
// gardé entre deux pages vit dans le paquet pagination, qui explique pourquoi
// c'est un instantané.

// taillePage dit si la recherche est paginée, et avec quelle taille de page.
//
// Trois cas rendent une recherche ORDINAIRE alors qu'un contrôle est présent :
//
//   - taille demandée à zéro, sans cookie : le client ne demande pas de page ;
//   - taille de page ≥ sizeLimit : la RFC 2696 §3 demande d'ignorer le contrôle,
//     la réponse tenant dans une seule page de toute façon ;
//   - session non liée : seuls le RootDSE et le sous-schéma lui sont ouverts, et
//     ils tiennent en une entrée. Aucun état n'est jamais gardé pour un inconnu.
//
// La taille rendue est plafonnée par MaxPageSize : le client propose, le
// serveur peut rendre moins.
func taillePage(op ldapstorage.SearchRequest, liée bool) (int, bool) {
	if op.Page == nil || op.Page.Size <= 0 || !liée {
		return 0, false
	}
	if op.SizeLimit > 0 && op.Page.Size >= op.SizeLimit {
		return 0, false
	}
	return plafonnerPage(op.Page.Size), true
}

func plafonnerPage(demandée int) int {
	if max := ldapstorage.MaxPageSize; max > 0 && demandée > max {
		return max
	}
	return demandée
}

// bornePaginee est le nombre d'entrées qu'une recherche paginée peut rendre en
// tout : la borne du serveur, que le sizeLimit du client ne peut que réduire.
//
// Ce n'est PAS MaxSearchEntries : la pagination existe pour lire au-delà.
func bornePaginee(sizeLimit int) int {
	borne := ldapstorage.MaxPagedSearchEntries
	if sizeLimit > 0 && (borne <= 0 || sizeLimit < borne) {
		return sizeLimit
	}
	return borne
}

// empreinteRecherche résume ce qui DÉFINIT une recherche : base, portée,
// filtre, attributs, typesOnly.
//
// Elle est comparée à chaque page. Un client qui change de filtre en cours de
// route recevrait sinon la suite de l'ANCIENNE recherche en croyant lire la
// nouvelle — une réponse fausse, sans erreur d'aucun côté.
//
// Les limites n'y entrent pas : elles bornent la lecture, elles ne changent pas
// ce qui est lu.
func empreinteRecherche(op ldapstorage.SearchRequest) string {
	attributs := make([]string, len(op.Attributes))
	for i, a := range op.Attributes {
		attributs[i] = strings.ToLower(a)
	}
	sort.Strings(attributs)

	// Le filtre passe par JSON : tous ses champs y entrent, sous-filtres
	// compris, y compris ceux qu'on lui ajoutera plus tard.
	filtre, err := json.Marshal(op.Filter)
	if err != nil {
		filtre = []byte(fmt.Sprintf("%p", op.Filter))
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%t\x00%s\x00", strings.ToLower(strings.TrimSpace(op.BaseObject)),
		op.Scope, op.TypesOnly, strings.Join(attributs, ","))
	h.Write(filtre)
	return hex.EncodeToString(h.Sum(nil))
}

// servirPremierePage fige le résultat d'une recherche et en sert le début.
func servirPremierePage(conn net.Conn, messageID int, op ldapstorage.SearchRequest, username, baseDN string,
	trouvées []ldapinterface.LDAPEntry, taille int, début time.Time) {
	borne := bornePaginee(op.SizeLimit)
	tronquée := borne > 0 && len(trouvées) > borne
	if tronquée {
		trouvées = trouvées[:borne]
	}

	// Le reste est rangé AVANT le premier envoi : si le serveur ne peut pas le
	// garder, le client doit recevoir un refus, pas une première page sans
	// suite — qu'il prendrait pour le résultat entier.
	page, err := pagination.Servir(conn, username, empreinteRecherche(op), trouvées, taille, tronquée)
	if err != nil {
		if errors.Is(err, pagination.ErrTropTenu) {
			ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
				"recherche paginée de %s refusée, trop d'entrées déjà tenues pour d'autres "+
					"(plafond MaxPagedEntriesHeld=%d)", username, ldapstorage.MaxPagedEntriesHeld))
			response.SendLDAPSearchFailureCode(conn, messageID, ldapstorage.ResultBusy,
				"too many paged searches in progress, retry later")
			return
		}
		ldapjournal.Ecrire(conn, "ERROR", logs.CodeNone, "ouverture d'une recherche paginée : "+err.Error())
		response.SendLDAPSearchFailure(conn, messageID, "paged search could not be started")
		return
	}
	terminerPage(conn, messageID, op, username, baseDN, page, début)
}

// servirPageSuivante répond à une requête qui porte un cookie.
func servirPageSuivante(conn net.Conn, messageID int, op ldapstorage.SearchRequest, username, baseDN string) {
	// Taille zéro AVEC un cookie : le client abandonne la recherche (RFC 2696
	// §3). On rend la mémoire et on confirme, sans entrée et sans cookie.
	if op.Page.Size == 0 {
		pagination.Abandonner(conn, op.Page.Cookie)
		response.SendLDAPSearchResultDonePage(conn, messageID, ldapstorage.ResultSuccess, "",
			ldapstorage.PagedResults{})
		return
	}

	page, err := pagination.Reprendre(conn, op.Page.Cookie, username, empreinteRecherche(op),
		plafonnerPage(op.Page.Size))
	if err != nil {
		// UNE réponse pour tous les motifs : le client n'a rien à faire de la
		// différence, et la lui donner renseignerait sur ce qui existe chez les
		// autres. Le journal, lui, la porte.
		ldapjournal.Ecrire(conn, "WARNING", logs.CodeNone, fmt.Sprintf(
			"page suivante refusée à %s sur baseDN=%s : %s", username, baseDN, err.Error()))
		response.SendLDAPSearchFailureCode(conn, messageID, ldapstorage.ResultUnwillingToPerform,
			"paged results cookie is invalid or expired")
		return
	}
	terminerPage(conn, messageID, op, username, baseDN, page, time.Now())
}

// terminerPage envoie les entrées d'une page puis le SearchResultDone qui porte
// le cookie.
func terminerPage(conn net.Conn, messageID int, op ldapstorage.SearchRequest, username, baseDN string,
	page pagination.Page, début time.Time) {
	if !envoyerEntrees(conn, messageID, op, username, baseDN, page.Entrees, début) {
		// Délai dépassé ou client parti : la suite ne sera jamais demandée avec
		// ce cookie, que le client n'a pas reçu. On rend la mémoire tout de suite.
		pagination.Abandonner(conn, page.Cookie)
		return
	}

	code, diagnostic := ldapstorage.ResultSuccess, ""
	if len(page.Cookie) == 0 && page.Tronque {
		// Dernière page d'une recherche qui a atteint une borne : le client doit
		// savoir qu'il n'a pas tout lu.
		code, diagnostic = ldapstorage.ResultSizeLimitExceeded, "size limit exceeded"
	}

	// Sur la ligne de l'opération : le total de la recherche, et s'il reste des
	// pages. Le nombre d'entrées de CETTE page y est déjà.
	j := ldapjournal.EnCours(conn)
	j.Noter("total", page.Total)
	if len(page.Cookie) > 0 {
		j.Noter("suite", "oui")
	} else {
		j.Noter("suite", "non")
	}

	response.SendLDAPSearchResultDonePage(conn, messageID, code, diagnostic,
		ldapstorage.PagedResults{Size: page.Total, Cookie: page.Cookie})
}
