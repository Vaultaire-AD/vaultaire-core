package ldapparser

import (
	ldapstorage "vaultaire/serveur/ldap/LDAP_Storage"
	"vaultaire/serveur/logs"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type SearchRequest struct{}

func (s SearchRequest) OpType() string { return "SearchRequest" }

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
		return nil, fmt.Errorf("unsupported protocolOp tag: %d", p.Tag)
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
		return nil, fmt.Errorf("failed to parse protocolOp: %v", err)
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
