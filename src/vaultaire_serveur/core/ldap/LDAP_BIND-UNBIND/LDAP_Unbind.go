package ldapbindunbind

import (
	"fmt"
	"net"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	"vaultaire/core/logs"
)

// func parseUnbindRequestManual(data []byte) error {
// 	if len(data) < 2 || data[0] != 0x42 {
// 		return fmt.Errorf("not an Unbind Request tag")
// 	}
// 	length := int(data[1])
// 	if length != 0 {
// 		return fmt.Errorf("unexpected length for Unbind request")
// 	}
// 	return nil
// }

// HandleUnbindRequest traite un UnbindRequest.
//
// # Il ne répond RIEN, et c'est la règle
//
// RFC 4511 §4.3 : « The Unbind operation ... has no response. » C'est la seule
// opération du protocole dans ce cas — partout ailleurs, se taire est un défaut.
//
// La version antérieure envoyait une BindResponse, construite à la main et
// étiquetée [APPLICATION 1], avec un commentaire qui reconnaissait déjà que
// c'était « non standard ». Le client, qui n'attend rien, recevait un message
// non sollicité sur une connexion qu'il considérait comme close : selon
// l'implémentation, cela produit une erreur de protocole ou une trame orpheline
// dans ses journaux.
//
// L'encodage manuel portait par ailleurs le même défaut que les autres :
// byte(messageID) tronquait au-delà de 255.
//
// # La connexion est fermée ici
//
// La RFC demande aux deux parties de fermer après un unbind. Se contenter
// d'oublier la session laissait la boucle de lecture attendre un EOF que le
// client n'envoie pas toujours — une connexion, et sa goroutine, immobilisées
// jusqu'à expiration TCP.
func HandleUnbindRequest(messageID int, conn net.Conn) {
	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: unbind messageID=%d depuis %s",
		messageID, conn.RemoteAddr()))

	ldapsessionmanager.ClearSession(conn)
	if err := conn.Close(); err != nil {
		logs.Write_Log("DEBUG", "ldap: fermeture après unbind : "+err.Error())
	}
}
