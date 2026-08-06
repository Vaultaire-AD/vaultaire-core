package ldapparser

import (
	"fmt"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func parseBindRequest(p *ber.Packet) (ldapstorage.BindRequest, error) {
	if len(p.Children) < 3 {
		return ldapstorage.BindRequest{}, fmt.Errorf("BindRequest has too few children")
	}

	versionPacket := p.Children[0]
	versionInt64, ok := versionPacket.Value.(int64)
	if !ok {
		return ldapstorage.BindRequest{}, fmt.Errorf("BindRequest version not int64")
	}
	version := int(versionInt64)

	namePacket := p.Children[1]
	name, ok := namePacket.Value.(string)
	if !ok {
		return ldapstorage.BindRequest{}, fmt.Errorf("BindRequest name not string")
	}

	// L'ÉTIQUETTE du choix d'authentification, et pas seulement son contenu.
	//
	// AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
	//                                   sasl   [3] SaslCredentials }
	//
	// La version antérieure lisait Data.String() sans regarder l'étiquette. Un
	// bind SASL — que le RootDSE invitait alors à tenter — voyait son contenu DER
	// brut pris pour un mot de passe, et le client recevait « invalid
	// credentials » : un message qui l'envoie vérifier son mot de passe alors que
	// c'est la méthode qui n'est pas gérée.
	authPacket := p.Children[2]
	simple := authPacket.ClassType == ber.ClassContext && authPacket.Tag == 0

	password := ""
	if simple {
		password = authPacket.Data.String()
	}

	return ldapstorage.BindRequest{
		Version:        version,
		Name:           name,
		Authentication: []byte(password),
		SimpleAuth:     simple,
		// Anonymat au sens de la RFC 4513 §5.1.1 : DN vide ET mot de passe vide.
		// Un DN vide avec un mot de passe est un bind « non authentifié », que le
		// gestionnaire refuse séparément.
		Anonymous: name == "" && password == "",
	}, nil
}

// func parseBindRequest(p *ber.Packet) (ldapstorage.BindRequest, error) {
// 	if len(p.Children) < 3 {
// 		return ldapstorage.BindRequest{}, fmt.Errorf("BindRequest has too few children")
// 	}
// 	// version (INTEGER)
// 	versionPacket := p.Children[0]
// 	versionInt64, ok := versionPacket.Value.(int64)
// 	if !ok {
// 		return ldapstorage.BindRequest{}, fmt.Errorf("BindRequest version not int64")
// 	}
// 	version := int(versionInt64)

// 	// name (LDAPDN : string)
// 	namePacket := p.Children[1]
// 	name, ok := namePacket.Value.(string)
// 	if !ok {
// 		return ldapstorage.BindRequest{}, fmt.Errorf("BindRequest name not string")
// 	}

// 	// authentication (simplifié : on prend juste le raw bytes)
// 	authPacket := p.Children[2]
// 	authentication := authPacket.Bytes()

// 	return ldapstorage.BindRequest{
// 		Version:        version,
// 		Name:           name,
// 		Authentication: authentication,
// 	}, nil
// }
