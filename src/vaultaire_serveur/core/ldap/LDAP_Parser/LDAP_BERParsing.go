package ldapparser

import (
	"fmt"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"

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

	logs.Write_Log("DEBUG", fmt.Sprintf("ldap: protocolOp tag=%d class=%d", p.Tag, p.ClassType))

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
		logs.Write_Log("WARNING", fmt.Sprintf("Unsupported protocolOp tag: %d", p.Tag))
		return nil, UnsupportedOperationError{Tag: int(p.Tag)}
	}
}

func parseControls(p *ber.Packet) []ldapstorage.LDAPControl {
	var controls []ldapstorage.LDAPControl

	for _, child := range p.Children {
		if child.Tag != ber.TagSequence {
			continue
		}
		var control ldapstorage.LDAPControl
		if len(child.Children) > 0 {
			control.ControlType, _ = child.Children[0].Value.(string)
		}
		if len(child.Children) > 1 {
			control.Criticality, _ = child.Children[1].Value.(bool)
		}
		if len(child.Children) > 2 {
			control.ControlValue = child.Children[2].ByteValue
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
