package ldapparser

import (
	"fmt"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type SearchRequest struct{}

func (s SearchRequest) OpType() string { return "SearchRequest" }

// UnsupportedOperationError désigne une opération que le serveur ne met pas en
// œuvre, en portant son étiquette.
//
// L'étiquette est indispensable : c'est elle qui dit quel TYPE de réponse
// renvoyer. Un client qui reçoit un SearchResultDone pour son ModifyRequest ne
// fait pas le lien avec sa requête et attend jusqu'à expiration.
//
// La version antérieure renvoyait une erreur ordinaire, et l'appelant faisait
// « continue » sans rien envoyer — le client attendait alors une réponse qui ne
// venait jamais.
type UnsupportedOperationError struct {
	Tag int
}

func (e UnsupportedOperationError) Error() string {
	return fmt.Sprintf("opération LDAP non supportée : étiquette %d", e.Tag)
}

func parseProtocolOp(p *ber.Packet) (ldapstorage.LDAPProtocolOperation, error) {
	if p.ClassType != ber.ClassApplication {
		return nil, fmt.Errorf("protocolOp should be application class")
	}

	switch p.Tag {
	case 0: // BindRequest
		return parseBindRequest(p)

	case 2: // UnbindRequest
		return parseUnBindRequest()

	case 23: // ModifyResponse / ExtendedRequest
		return parseExtendedRequest(p)

	case 3: // SearchRequest
		// On appelle parseSearchRequest pour obtenir un SearchRequest complet
		sr, err := parseSearchRequest(p)
		if err != nil {
			return nil, err
		}
		return sr, nil

	default:
		// Sans ligne de journal : l'appelant reçoit l'erreur et l'écrit, avec
		// l'identifiant de la connexion et l'adresse du client — ce que ce
		// décodeur, qui ne voit que des octets, ne connaît pas.
		return nil, UnsupportedOperationError{Tag: int(p.Tag)}
	}
}

// parseControls décode la liste des contrôles d'un message — RFC 4511 §4.1.11 :
//
//	Control ::= SEQUENCE {
//	        controlType   LDAPOID,
//	        criticality   BOOLEAN DEFAULT FALSE,
//	        controlValue  OCTET STRING OPTIONAL }
//
// # Les champs se reconnaissent à leur TYPE, pas à leur rang
//
// `criticality` a une valeur par défaut : un client qui envoie FALSE l'omet,
// comme le veut l'encodage DER. La séquence n'a alors que deux éléments, et le
// second est la VALEUR.
//
// La version antérieure lisait par position — le deuxième comme un booléen, le
// troisième comme la valeur. Sur un contrôle non critique, elle ne trouvait donc
// pas de booléen (sans conséquence) et ne trouvait pas de valeur non plus : le
// contrôle arrivait VIDE. Rien ne s'en apercevait tant que tous les contrôles
// étaient ignorés ; la pagination (point 130), que la plupart des clients
// demandent sans la marquer critique, aurait été illisible.
func parseControls(p *ber.Packet) []ldapstorage.LDAPControl {
	var controls []ldapstorage.LDAPControl

	for _, child := range p.Children {
		if child.Tag != ber.TagSequence || len(child.Children) == 0 {
			continue
		}
		var control ldapstorage.LDAPControl
		control.ControlType, _ = child.Children[0].Value.(string)

		for _, champ := range child.Children[1:] {
			if champ.ClassType != ber.ClassUniversal {
				continue
			}
			switch champ.Tag {
			case ber.TagBoolean:
				control.Criticality, _ = champ.Value.(bool)
			case ber.TagOctetString:
				control.ControlValue = champ.ByteValue
			}
		}
		controls = append(controls, control)
	}
	return controls
}

// ParseLDAPMessage décode un LDAPMessage.
//
// Le troisième retour booléen « modify » a disparu. Il valait true quand
// protocolOp portait l'étiquette 16, que l'appelant traitait comme une erreur de
// protocole avant de FERMER la connexion.
//
// La classe n'était pas vérifiée : l'étiquette 16 en classe universelle est bien
// une SEQUENCE mal placée, mais en classe APPLICATION c'est un AbandonRequest —
// une opération parfaitement légitime, à laquelle la RFC 4511 §4.11 demande
// justement de ne PAS répondre. Le serveur fermait donc la connexion d'un client
// qui abandonnait une recherche.
func ParseLDAPMessage(packet []byte) (*ldapstorage.LDAPParsedReceivedMessage, error) {
	p := ber.DecodePacket(packet)
	if p == nil {
		return nil, fmt.Errorf("BER decode returned nil packet")
	}

	if p.Tag != ber.TagSequence || p.ClassType != ber.ClassUniversal {
		return nil, fmt.Errorf("not a valid LDAP message")
	}

	if len(p.Children) < 2 {
		return nil, fmt.Errorf("LDAP message has too few children")
	}

	// --- MessageID (Tag: INTEGER)
	messageIDPacket := p.Children[0]
	if messageIDPacket.Tag != ber.TagInteger {
		return nil, fmt.Errorf("expected INTEGER for messageID")
	}
	messageID, ok := messageIDPacket.Value.(int64)
	if !ok {
		return nil, fmt.Errorf("messageID not an int64")
	}

	// --- ProtocolOp (CHOICE)
	protocolOpPacket := p.Children[1]
	protocolOp, err := parseProtocolOp(protocolOpPacket)
	if err != nil {
		return nil, err
	}

	// --- Controls (optional, context-specific [0])
	var controls []ldapstorage.LDAPControl
	if len(p.Children) > 2 {
		controlPacket := p.Children[2]
		if controlPacket.Tag == 0 && controlPacket.ClassType == ber.ClassContext {
			controls = parseControls(controlPacket)
		}
	}

	return &ldapstorage.LDAPParsedReceivedMessage{
		MessageID:  int(messageID),
		ProtocolOp: protocolOp,
		Controls:   controls,
	}, nil
}
