package response

import (
	"fmt"
	"net"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Conservé pour les appelants historiques.
//
// Deprecated: préférer SendLDAPSearchFailureCode, qui dit POURQUOI.
const LDAPResultOperationsError = ldapstorage.ResultOperationsError

// SendLDAPSearchFailureCode termine une recherche en échec avec un code précis.
//
// # Pourquoi le code compte
//
// Toutes les recherches en échec renvoyaient `operationsError` (1), qui veut dire
// « le serveur a eu un problème ». Un client recevait donc le même code pour
// « ré-authentifie-toi », « tu n'as pas le droit » et « la base est tombée ».
//
// Les trois appellent des réactions différentes : rejouer un bind, prévenir un
// administrateur, réessayer plus tard. Sans distinction, un client bien écrit ne
// peut rien faire de mieux qu'un client mal écrit.
func SendLDAPSearchFailureCode(conn net.Conn, messageID, resultCode int, errMsg string) error {
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ber.Tag(ldapstorage.AppSearchResultDone), nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		uint64(resultCode), "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		"", "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		errMsg, "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	if _, err := conn.Write(finalPacket.Bytes()); err != nil {
		logs.Write_Log("WARNING", "ldap: envoi du SearchResultDone en échec : "+err.Error())
		return fmt.Errorf("failed to send SearchResultDone: %v", err)
	}
	return nil
}

// SendLDAPSearchFailure signale une erreur interne du serveur.
//
// Réservée aux vraies pannes — base injoignable, scope invalide. Pour un refus
// d'accès ou une authentification manquante, employer
// SendLDAPSearchFailureCode avec le code correspondant.
func SendLDAPSearchFailure(conn net.Conn, messageID int, errMsg string) error {
	return SendLDAPSearchFailureCode(conn, messageID, ldapstorage.ResultOperationsError, errMsg)
}

// SendLDAPNoSuchObject termine une recherche dont le baseObject ne désigne
// aucune entrée — RFC 4511, code 32.
//
// # Pourquoi une fonction à part
//
// Parce qu'elle est la seule à renseigner `matchedDN`. Ce champ est vide partout
// ailleurs, et c'est correct : il n'a de sens que pour ce code-là. Il dit au
// client OÙ le chemin se rompt — « dc=enov,dc=local existe, dc=admin dessous
// n'existe pas » — au lieu de le laisser deviner lequel des composants de son DN
// est en cause.
//
// matchedDN peut être vide : cela veut dire qu'aucun ancêtre n'existe non plus.
func SendLDAPNoSuchObject(conn net.Conn, messageID int, matchedDN string) error {
	resultDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ber.Tag(ldapstorage.AppSearchResultDone), nil, "SearchResultDone")
	resultDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated,
		uint64(ldapstorage.ResultNoSuchObject), "resultCode"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		matchedDN, "matchedDN"))
	resultDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		"no such object", "diagnosticMessage"))

	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger,
		uint64(messageID), "Message ID"))
	finalPacket.AppendChild(resultDone)

	if _, err := conn.Write(finalPacket.Bytes()); err != nil {
		logs.Write_Log("WARNING", "ldap: envoi du noSuchObject en échec : "+err.Error())
		return fmt.Errorf("failed to send noSuchObject: %v", err)
	}
	return nil
}
