package newmodule

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net"
	"runtime/debug"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// failingConnector rend un *sql.DB valide dont toute requête échoue.
//
// Passer nil comme *sql.DB ne convient pas : la première requête panique dans
// database/sql, ce qui masquerait le défaut qu'on cherche à mesurer par un
// défaut du test lui-même. C'est exactement l'erreur de la première version de
// ce test, qui échouait pour la mauvaise raison.
type failingConnector struct{}

func (failingConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("base indisponible (test)")
}
func (failingConnector) Driver() driver.Driver { return nil }

// TestSearchSansSessionNePaniquePas couvre un déni de service NON AUTHENTIFIÉ.
//
// # Le chemin d'origine
//
//  1. le client ouvre une connexion       → InitLDAPSession crée la session
//  2. bind sur le DN « vaultaire »         → la session était SUPPRIMÉE,
//     la connexion restait ouverte
//  3. recherche avec baseObject vide       → RootDSE
//
// Les deux gardes de HandleSearchRequest étaient contournées par le même fait —
// baseObject vide — puis session.Username était évalué sur un pointeur nil.
//
// Comme le serveur n'avait aucun recover(), la panique dans la goroutine de
// session arrêtait le processus entier : Ducky, interface web, DNS et API
// compris. Trois paquets suffisaient, sans le moindre identifiant.
//
// Deux corrections indépendantes le ferment :
//   - le refus de bind appelle désormais ResetBindInfo, qui conserve la session ;
//   - HandleSearchRequest travaille sur des valeurs locales et ne déréférence
//     jamais le pointeur de session.
func TestSearchSansSessionNePaniquePas(t *testing.T) {
	client, serveur := net.Pipe()
	defer client.Close()
	defer serveur.Close()

	// net.Pipe est synchrone : sans lecteur, la première écriture du serveur
	// bloquerait indéfiniment.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	db := sql.OpenDB(failingConnector{})
	defer db.Close()

	// Aucun InitLDAPSession : c'est l'état exact que laissait le rejet du compte
	// « vaultaire ».
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sur une recherche sans session : %v\n%s", r, debug.Stack())
		}
	}()

	for _, base := range []string{"", "cn=schema", "CN=Schema", "cn=subschema"} {
		HandleSearchRequest(db, ldapstorage.SearchRequest{BaseObject: base, Scope: 0}, 1, serveur)
	}

	// Une base ordinaire sans session doit être refusée proprement, pas paniquer.
	HandleSearchRequest(db, ldapstorage.SearchRequest{
		BaseObject: "ou=users,dc=vaultaire,dc=fr", Scope: 2,
	}, 2, serveur)
}
