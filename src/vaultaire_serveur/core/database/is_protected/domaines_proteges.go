package isprotected

import (
	"database/sql"
	"strings"
	"sync"
	"time"

	"vaultaire/core/database"
	"vaultaire/core/logs"
)

// Le domaine du groupe superadmin, et tout ce qui vit dessous — TO-DO 96.
//
// # Le chemin d'escalade que cela ferme
//
// Le groupe `vaultaire` porte `vaultaire_all` : tous les droits, sur tous les
// domaines. Il est rattaché à un domaine comme n'importe quel groupe — par
// défaut `vaultaire.fr`.
//
// Or l'action `group.add_user` exige `write:add:user` sur l'union des domaines
// du groupe visé et de l'utilisateur visé, et la propagation de domaine est un
// suffixe. Un délégué portant ce droit sur `fr` ou sur `vaultaire.fr` exécutait
// donc `add -u son_compte -g vaultaire` et devenait superadmin. Aucune des dix
// gardes du paquet ne couvrait l'ENTRÉE dans le groupe protégé — seulement le
// retrait, le renommage et la suppression.
//
// # Pourquoi une garde sur le DOMAINE et pas sur l'action
//
// Fermer `group.add_user` aurait fermé un chemin. Le domaine du groupe superadmin
// est atteignable par toutes les écritures qui raisonnent par domaine : créer un
// groupe dessous, y rattacher une permission, y déplacer une machine. Une garde
// par action aurait été une liste à compléter à chaque action ajoutée — et la
// prochaine aurait été oubliée.
//
// La garde vit donc dans le contrôle d'accès en ÉCRITURE, qui est l'entonnoir
// commun de la ligne de commande, du portail et de l'API.
//
// # Ce qui reste possible, et c'est le but
//
// Ajouter quelqu'un au groupe `vaultaire` — le geste normal pour confier
// l'administration. Il est réservé aux membres de ce groupe : celui qui donne le
// pouvoir doit déjà l'avoir.
//
// # Le domaine est LU, pas codé en dur
//
// `IsProtectedUser` et `IsProtectedGroup` comparent à une constante, parce qu'un
// nom de compte et un nom de groupe sont fixés par l'amorçage. Un domaine, non :
// il est en base, et un annuaire peut parfaitement rattacher son groupe
// superadmin à autre chose. Coder `vaultaire.fr` en dur aurait protégé un
// domaine que personne n'utilise, et laissé le vrai ouvert.

// DomaineProtegeParDefaut sert quand la base ne répond pas, ou ne rattache
// aucun domaine au groupe superadmin.
//
// Fail-closed : sans repli, une panne de lecture rendrait « aucun domaine
// protégé », c'est-à-dire ouvrirait exactement ce que cette garde ferme — et au
// moment où le serveur va mal. La valeur est celle de l'amorçage.
const DomaineProtegeParDefaut = "vaultaire.fr"

// Les domaines changent à peu près jamais, et la garde est traversée par chaque
// écriture du produit. Un cache court évite une lecture par contrôle sans
// rendre un changement invisible plus d'une minute.
var (
	domainesMu        sync.Mutex
	domainesCache     []string
	domainesExpire    time.Time
	dureeCacheDomaine = time.Minute
)

// DomainesProteges rend les domaines du groupe superadmin.
func DomainesProteges(db *sql.DB) []string {
	domainesMu.Lock()
	defer domainesMu.Unlock()

	if time.Now().Before(domainesExpire) && len(domainesCache) > 0 {
		return domainesCache
	}

	domaines := lireDomainesDuGroupeProtege(db)
	if len(domaines) == 0 {
		// Ni erreur ni domaine : on protège quand même le domaine d'amorçage.
		// Une base sans rattachement est une base dont on ne sait rien, pas une
		// base sans superadmin.
		domaines = []string{DomaineProtegeParDefaut}
	}

	domainesCache = domaines
	domainesExpire = time.Now().Add(dureeCacheDomaine)
	return domaines
}

// OublierDomainesProteges vide le cache.
//
// Pour les tests, et pour un appelant qui vient de modifier le rattachement du
// groupe protégé : sans cela, sa propre modification resterait invisible une
// minute, ce qui se lit comme un défaut.
func OublierDomainesProteges() {
	domainesMu.Lock()
	domainesCache = nil
	domainesExpire = time.Time{}
	domainesMu.Unlock()
}

func lireDomainesDuGroupeProtege(db *sql.DB) []string {
	if db == nil {
		return nil
	}

	rows, err := db.Query(`
		SELECT dg.domain_name
		  FROM domain_group dg
		  JOIN groups g ON g.id_group = dg.d_id_group
		 WHERE g.group_name = ?`, ProtectedGroupName)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"protection: domaines du groupe "+ProtectedGroupName+" illisibles, "+
				"repli sur "+DomaineProtegeParDefaut+" : "+err.Error())
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			continue
		}
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// EstDomaineProtege dit si un domaine relève du groupe superadmin.
//
// Le domaine lui-même ET ses sous-domaines : « protégé dans son intégralité »
// n'aurait aucun sens si l'on pouvait créer `x.vaultaire.fr` pour y travailler
// librement. C'est la même règle de propagation que le contrôle d'accès
// ordinaire, appliquée dans l'autre sens.
func EstDomaineProtege(db *sql.DB, domaine string) bool {
	d := strings.ToLower(strings.TrimSpace(domaine))
	if d == "" {
		return false
	}
	for _, protege := range DomainesProteges(db) {
		if d == protege || strings.HasSuffix(d, "."+protege) {
			return true
		}
	}
	return false
}

// GroupesContiennentLeGroupeProtege dit si l'appelant est superadmin, à partir
// de ses identifiants de groupe.
//
// Par identifiant et non par nom d'utilisateur : le contrôle d'accès ne connaît
// que les groupes de l'appelant, et lui faire retrouver le compte pour le
// rechercher ensuite ajouterait une lecture et une occasion de se tromper de
// personne.
func GroupesContiennentLeGroupeProtege(db *sql.DB, groupIDs []int) bool {
	if db == nil || len(groupIDs) == 0 {
		return false
	}

	var idProtege int
	err := db.QueryRow(`SELECT id_group FROM groups WHERE group_name = ?`,
		ProtectedGroupName).Scan(&idProtege)
	if err != nil {
		// Refus en cas d'erreur, comme IsSuperadmin : une panne de base ne doit
		// pas ouvrir le domaine le plus sensible du produit.
		if err != sql.ErrNoRows {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"protection: groupe "+ProtectedGroupName+" illisible : "+err.Error())
		}
		return false
	}

	for _, id := range groupIDs {
		if id == idProtege {
			return true
		}
	}
	return false
}

// Le paquet database est importé pour rester cohérent avec IsSuperadmin, qui
// passe par lui. Référence explicite pour que l'import ne soit pas retiré par
// mégarde le jour où cette fonction change.
var _ = database.GetDatabase
