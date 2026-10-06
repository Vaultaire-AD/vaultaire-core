package ldapbindunbind

import (
	"net"
	"runtime/debug"
	"testing"
	"time"

	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Les quatre formes d'un bind simple (TO-DO 128).
//
// Le défaut était un écart entre un commentaire et son code : le commentaire
// citait la RFC 4513 §5.1.2 — DN fourni, mot de passe vide — et le code
// refusait le cas voisin, DN vide et mot de passe fourni. La table est donc
// écrite ici en entier, avec le paragraphe de chaque cas.
func TestLesQuatreFormesDeBind(t *testing.T) {
	cas := []struct {
		nom, motDePasse string
		attendu         formeDeBind
		pourquoi        string
	}{
		{"", "", bindAnonyme, "§5.1.1 : les deux vides, c'est l'anonymat"},
		{"uid=alice,ou=users,dc=acme,dc=lan", "", bindNonAuthentifie,
			"§5.1.2 : DN fourni et mot de passe vide — le cas que le commentaire nommait sans que le code le traite"},
		{"", "secret", bindSansNom, "hors RFC : un mot de passe sans DN ne désigne personne"},
		{"uid=alice,ou=users,dc=acme,dc=lan", "secret", bindNomEtMotDePasse,
			"§5.1.3 : le seul bind qui identifie quelqu'un"},
	}
	for _, c := range cas {
		op := ldapstorage.BindRequest{Version: 3, Name: c.nom,
			Authentication: []byte(c.motDePasse), SimpleAuth: true}
		if got := natureDuBind(op); got != c.attendu {
			t.Errorf("natureDuBind(DN=%q, mot de passe=%q) = %d, attendu %d — %s",
				c.nom, c.motDePasse, got, c.attendu, c.pourquoi)
		}
	}
}

// lireCodeDeBind lit une BindResponse sur le côté client et rend son code.
func lireCodeDeBind(t *testing.T, client net.Conn) int {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	paquet, err := ber.ReadPacket(client)
	if err != nil {
		t.Fatalf("aucune réponse du gestionnaire de bind : %v", err)
	}
	if len(paquet.Children) < 2 || len(paquet.Children[1].Children) < 1 {
		t.Fatalf("réponse malformée : %d enfant(s)", len(paquet.Children))
	}
	if tag := int(paquet.Children[1].Tag); tag != ldapstorage.AppBindResponse {
		t.Fatalf("étiquette de réponse %d, attendu BindResponse (%d)", tag, ldapstorage.AppBindResponse)
	}
	code, ok := paquet.Children[1].Children[0].Value.(int64)
	if !ok {
		t.Fatalf("code de résultat illisible : %T", paquet.Children[1].Children[0].Value)
	}
	return int(code)
}

// Le bind non authentifié est refusé AVANT toute lecture de la base, et sans
// laisser de session liée.
//
// Ce test tourne sans base : la connexion globale n'est pas ouverte. Si le
// refus arrivait après la recherche du compte, le gestionnaire toucherait une
// base absente et paniquerait — c'est ce qui prouve « avant ».
func TestBindSansIdentiteRefuseAvantLaBase(t *testing.T) {
	cas := []struct {
		titre, nom, motDePasse string
	}{
		{"§5.1.2 — DN fourni, mot de passe vide", "uid=alice,ou=users,dc=acme,dc=lan", ""},
		{"DN vide, mot de passe fourni", "", "secret"},
	}
	for _, c := range cas {
		t.Run(c.titre, func(t *testing.T) {
			client, serveur := net.Pipe()
			defer client.Close()
			defer serveur.Close()

			ldapsessionmanager.InitLDAPSession(serveur)
			defer ldapsessionmanager.ClearSession(serveur)
			// Une session DÉJÀ liée : un bind refusé doit la ramener à l'état
			// non authentifié (RFC 4511 §4.2.1), pas la laisser à son ancien
			// titulaire.
			ldapsessionmanager.SetBindInfo(serveur, "bob", "uid=bob,ou=users,dc=acme,dc=lan")

			fini := make(chan struct{})
			go func() {
				defer close(fini)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PANIQUE : le refus n'a pas eu lieu avant la lecture de la base.\n%v\n%s", r, debug.Stack())
						serveur.Close()
					}
				}()
				HandleBindRequest(ldapstorage.BindRequest{Version: 3, Name: c.nom,
					Authentication: []byte(c.motDePasse), SimpleAuth: true}, 7, serveur)
			}()

			if code := lireCodeDeBind(t, client); code != ldapstorage.ResultUnwillingToPerform {
				t.Errorf("code %d, attendu unwillingToPerform (%d) : c'est celui que la RFC 4513 §5.1.2 demande",
					code, ldapstorage.ResultUnwillingToPerform)
			}
			<-fini

			if s, ok := ldapsessionmanager.GetLDAPSession(serveur); !ok || s.IsBound || s.Username != "" {
				t.Errorf("après le refus la session est %+v : elle doit être non liée, sans nom", s)
			}
		})
	}
}
