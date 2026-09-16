package ldapresponse

import (
	"bytes"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

// TestMessageIDNonTronque couvre le SECOND bug du point 12 de la TO-DO.
//
// # Le défaut
//
//	msgID := []byte{0x02, 0x01, byte(messageID)}
//
// Trois octets figés : étiquette INTEGER, longueur 1, valeur sur UN octet. Le
// message 256 devenait donc 0, le 257 devenait 1, et ainsi de suite.
//
// # Pourquoi c'est le pire des deux
//
// Le bug de longueur (couvert par LDAP_Result_test.go) casse franchement le
// flux : le client voit un paquet malformé et se plaint. Celui-ci est SILENCIEUX
// — la réponse est parfaitement valide, elle porte simplement l'identifiant de
// quelqu'un d'autre.
//
// Un client qui garde sa connexion ouverte — SSSD, JumpServer, un pool
// applicatif — dépasse 255 opérations en quelques minutes, puis corrèle des
// réponses aux mauvaises requêtes. Symptôme typique : « marche en test, casse en
// production après quelques minutes ».
//
// # Ce que le test vérifie
//
// Que deux identifiants distincts produisent des paquets distincts, y compris
// de part et d'autre des seuils de 255 et 65535. La vérification ne porte pas
// sur l'encodage exact — c'est l'affaire de la bibliothèque — mais sur la
// propriété qui manquait : l'injectivité.
func TestMessageIDNonTronque(t *testing.T) {
	// Les couples qui collisionnaient avec l'ancien encodage sur un octet.
	collisions := []struct{ a, b int }{
		{0, 256},     // 256 & 0xFF == 0
		{1, 257},     // 257 & 0xFF == 1
		{42, 298},    // 298 & 0xFF == 42
		{255, 511},   // 511 & 0xFF == 255
		{1, 65537},   // deux seuils franchis
		{300, 65836}, //
	}

	for _, c := range collisions {
		paquetA := BuildResult(c.a, ldapstorage.AppBindResponse, ldapstorage.ResultSuccess, "", "ok")
		paquetB := BuildResult(c.b, ldapstorage.AppBindResponse, ldapstorage.ResultSuccess, "", "ok")

		if bytes.Equal(paquetA, paquetB) {
			t.Errorf("messageID %d et %d produisent le MÊME paquet : "+
				"le client corrélerait la réponse à la mauvaise requête", c.a, c.b)
		}
	}
}

// TestMessageIDGrandisSansCasser : un identifiant réaliste de session longue.
//
// Un pool applicatif atteint facilement des dizaines de milliers d'opérations.
// Le test vérifie qu'aucune valeur de cette plage ne produit de collision avec
// une autre.
func TestMessageIDGrandisSansCasser(t *testing.T) {
	vus := make(map[string]int)
	for _, id := range []int{1, 100, 255, 256, 1000, 65535, 65536, 100000, 1000000} {
		paquet := BuildResult(id, ldapstorage.AppSearchResultDone, ldapstorage.ResultSuccess, "", "")
		clé := string(paquet)
		if précédent, existe := vus[clé]; existe {
			t.Errorf("messageID %d produit le même paquet que %d", id, précédent)
			continue
		}
		vus[clé] = id

		// Un paquet vide signalerait un encodage qui a renoncé.
		if len(paquet) == 0 {
			t.Errorf("messageID %d : paquet vide", id)
		}
	}
}

// TestExtendedResponseMessageID : la même propriété sur l'autre constructeur.
//
// L'ExtendedResponse avait sa propre copie de l'encodage manuel, avec le même
// défaut. Deux constructeurs, deux fois le même bug à corriger — c'est
// précisément la raison d'être du paquet ldapresponse.
func TestExtendedResponseMessageID(t *testing.T) {
	a := BuildExtendedResult(0, ldapstorage.ResultSuccess, "", "", "", "dn:uid=alice")
	b := BuildExtendedResult(256, ldapstorage.ResultSuccess, "", "", "", "dn:uid=alice")

	if bytes.Equal(a, b) {
		t.Error("ExtendedResponse : messageID 0 et 256 produisent le même paquet")
	}
}
