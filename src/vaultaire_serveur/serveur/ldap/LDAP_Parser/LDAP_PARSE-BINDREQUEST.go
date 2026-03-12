package ldapparser

import (
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"fmt"

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

	authPacket := p.Children[2]

	// ⚠️ Récupérer le mot de passe en brut, car c’est un OctetString [0x80]
	password := string(authPacket.Data.String())

	return ldapstorage.BindRequest{
		Version:        version,
		Name:           name,
		Authentication: []byte(password),
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
