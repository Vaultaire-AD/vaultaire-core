package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	ldapparser "vaultaire/core/ldap/LDAP_Parser"
	ldapresponse "vaultaire/core/ldap/LDAP_RESPONSE"
	ldapsessionmanager "vaultaire/core/ldap/LDAP_SESSION-Manager"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/netguard"
	"vaultaire/core/proxiesconnus"
	"vaultaire/core/proxyproto"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ldapLimiter borne les connexions simultanées sur les écoutes LDAP et LDAPS.
//
// Un limiteur PARTAGÉ par les deux écoutes, délibérément : elles servent le même
// annuaire et consomment les mêmes descripteurs. Deux plafonds séparés
// laisseraient additionner les deux pour en obtenir le double.
//
// 500 au total et 20 par adresse : un client LDAP ouvre une connexion, parfois
// quelques-unes pour un pool. Vingt est large ; un annuaire n'est pas un serveur
// web.
var ldapLimiter = netguard.NewLimiter("ldap", 500, 20)

// PlafondLDAPParProxy est le plafond par adresse d'un PROXY du cluster.
//
// Toutes les applications d'un site relayées par un proxy arrivent de son
// adresse (TO-DO 72) : au plafond ordinaire de vingt, le site entier serait
// coupé à la vingt-et-unième connexion. Même motif que PlafondParProxy pour
// Ducky, à la taille d'un annuaire. Le plafond global, lui, reste commun.
const PlafondLDAPParProxy = 200

func plafondLDAPPourSource(source string) int {
	if proxiesconnus.EstUnProxy(source) {
		return PlafondLDAPParProxy
	}
	return 0
}

// preparerConnexion lit un éventuel en-tête PROXY v2, puis pose TLS pour LDAPS.
//
// La place au limiteur a été prise sur l'adresse du PAIR — le proxy, s'il y en
// a un. C'est voulu : c'est lui qui consomme les descripteurs. Ce qui compte
// par CLIENT, la limitation des échecs de bind, lit RemoteAddr, qui rend
// désormais l'adresse d'origine.
func preparerConnexion(conn net.Conn, protocol string, tlsConfig *tls.Config) (net.Conn, error) {
	c, err := proxyproto.Lire(conn, proxiesconnus.EstUnProxy, netguard.HandshakeReadTimeout)
	if err != nil {
		niveau := "WARNING"
		if errors.Is(err, proxyproto.ErrNonDeConfiance) {
			// Quelqu'un qui envoie un en-tête PROXY sans être un proxy du
			// cluster essaie de choisir l'adresse sous laquelle il est compté.
			niveau = "SECURITY"
		}
		logs.Write_LogCode(niveau, logs.CodeLDAPListen, fmt.Sprintf(
			"ldap: connexion %s de %s refusée : %v", protocol, netguard.SourceAddr(conn), err))
		return nil, err
	}
	if c.Relais != nil {
		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: connexion %s de %s relayée par le proxy %s",
			protocol, c.RemoteAddr(), c.Relais))
	}
	if tlsConfig != nil {
		return tls.Server(c, tlsConfig), nil
	}
	return c, nil
}

// Fonction générique utilisée par LDAP et LDAPS.
//
// tlsConfig non nul : LDAPS. TLS est posé APRÈS la lecture d'un éventuel
// en-tête PROXY, dans la goroutine de la connexion — jamais dans la boucle
// d'acceptation, qu'un pair lent bloquerait pour tout le monde.
func handleLDAPConnections(listener net.Listener, protocol string, tlsConfig *tls.Config) {
	ldapLimiter.DefinirPlafondPour(plafondLDAPPourSource)
	proxiesconnus.Demarrer()

	defer func() {
		if err := listener.Close(); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap: listener close failed: "+err.Error())
		}
	}()

	logs.Write_Log("INFO", "ldap: "+protocol+" listening on "+listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeLDAPListen, fmt.Sprintf("[%s] Erreur d’acceptation de connexion: %s", protocol, err))
			continue
		}

		// Même plafond que Ducky, et pour la même raison : le port LDAP accepte
		// des connexions d'inconnus, et chacune coûte un descripteur et une
		// goroutine. Refus silencieux — répondre dirait à un attaquant qu'il a
		// trouvé la limite.
		release, autorisé, motif := ldapLimiter.Acquire(conn)
		if !autorisé {
			logs.Write_LogCode("WARNING", logs.CodeLDAPListen,
				"ldap: connexion refusée depuis "+netguard.SourceAddr(conn)+" : "+motif)
			if cerr := conn.Close(); cerr != nil {
				logs.Write_Log("DEBUG", "ldap: fermeture après refus : "+cerr.Error())
			}
			continue
		}

		go func() {
			defer release()
			session, err := preparerConnexion(conn, protocol, tlsConfig)
			if err != nil {
				if cerr := conn.Close(); cerr != nil {
					logs.Write_Log("DEBUG", "ldap: fermeture après refus : "+cerr.Error())
				}
				return
			}
			handleLDAPSession(session, protocol)
		}()
	}
}

// Lecture et traitement d'une session LDAP unique
func handleLDAPSession(c net.Conn, protocol string) {
	// Filet de dernier recours : une panique ne doit coûter QUE cette
	// connexion.
	//
	// Sans lui, n'importe quel déréférencement nil dans le chemin LDAP
	// arrête le processus entier — donc aussi Ducky, l'interface web, le DNS
	// et l'API. Le port 389 est exposé et accepte des paquets d'inconnus :
	// c'est la surface la moins maîtrisée du produit, et celle qui mérite le
	// plus une barrière.
	//
	// Ce recover ne RÉPARE rien et ne doit pas servir d'excuse à ne pas
	// corriger la cause : il la rend survivable, et la journalise en
	// CRITICAL avec sa pile pour qu'elle soit corrigée.
	defer func() {
		if r := recover(); r != nil {
			logs.Write_LogCode("CRITICAL", logs.CodeLDAPListen, fmt.Sprintf(
				"ldap: panique traitée sur la session %s : %v\n%s",
				c.RemoteAddr(), r, debug.Stack()))
		}
	}()

	defer func() {
		ldapsessionmanager.ClearSession(c)
		if err := c.Close(); err != nil {
			logs.Write_Log("DEBUG", "ldap: connection close failed: "+err.Error())
		}
	}()

	ldapsessionmanager.InitLDAPSession(c)
	clientAddr := c.RemoteAddr().String()
	logs.Write_Log("INFO", "ldap: connection from "+clientAddr)

	for {
		// Réarmé avant CHAQUE lecture : le délai est absolu, pas glissant.
		//
		// Une session liée obtient le délai long, une session en cours de bind le
		// délai court — un client réel envoie son bind aussitôt connecté.
		sess, _ := ldapsessionmanager.GetLDAPSession(c)
		netguard.ArmReadDeadline(c, sess != nil && sess.IsBound)

		packet, err := readLDAPPacket(c)
		if err != nil {
			if err == io.EOF {
				logs.Write_Log("DEBUG", "ldap: client closed connection: "+clientAddr)
			} else {
				logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap: read packet failed from "+clientAddr+": "+err.Error())
			}
			return
		}

		logs.Write_Log("DEBUG", fmt.Sprintf("ldap: packet from %s: % X", clientAddr, packet))

		message, err := ldapparser.ParseLDAPMessage(packet)
		if err != nil {
			// Une opération non supportée reçoit une RÉPONSE, pas un silence.
			//
			// RFC 4511 §4.2 : toute opération appelle une réponse, y compris un
			// refus. La version antérieure faisait « continue » : le client
			// attendait alors jusqu'à sa propre expiration, sans jamais savoir
			// que le serveur avait décidé quelque chose.
			//
			// L'AbandonRequest est la seule exception, et elle est portée par
			// ResponseTagFor : la RFC lui interdit explicitement toute réponse.
			var unsupported ldapparser.UnsupportedOperationError
			if errors.As(err, &unsupported) {
				if appTag, wants := ldapstorage.ResponseTagFor(unsupported.Tag); wants {
					if sendErr := ldapresponse.SendResult(c, messageIDOf(packet), appTag,
						ldapstorage.ResultUnwillingToPerform, "",
						"operation not supported by this server"); sendErr != nil {
						logs.Write_Log("DEBUG", "ldap: "+sendErr.Error())
					}
				}
				logs.Write_Log("WARNING", fmt.Sprintf(
					"ldap: opération %d refusée depuis %s", unsupported.Tag, clientAddr))
				continue
			}

			// Trame illisible : le message est peut-être tronqué ou forgé. On ne
			// peut pas en extraire un messageID fiable, donc on ne répond pas et on
			// ferme — poursuivre la lecture d'un flux qu'on ne sait plus découper
			// ne produirait que du bruit.
			logs.Write_LogCode("ERROR", logs.CodeLDAPListen, "ldap: parse failed from "+clientAddr+": "+err.Error())
			return
		}

		// if storage.Debug {
		// 	printLDAPMessageDebug(message, protocol, clientAddr)
		// }

		ldapparser.DispatchLDAPOperation(message, message.MessageID, c)
	}
}

// messageIDOf extrait le messageID d'un paquet dont l'opération n'a pas pu être
// analysée.
//
// La réponse doit porter le MÊME identifiant que la requête, sinon le client ne
// la rattache à rien et attend quand même. L'en-tête, lui, reste lisible : c'est
// seulement le corps de l'opération qui n'est pas supporté.
//
// Retourne 0 si même l'en-tête est illisible — un identifiant faux vaut mieux
// que pas de réponse du tout, et 0 est une valeur qu'aucun client n'émet.
func messageIDOf(packet []byte) int {
	p := ber.DecodePacket(packet)
	if p == nil || len(p.Children) == 0 {
		return 0
	}
	if id, ok := p.Children[0].Value.(int64); ok {
		return int(id)
	}
	return 0
}

func SendLDAPError(conn net.Conn, messageID int, resultCode int, errMsg string) error {
	// 1. Construction de la réponse (LDAPResult)
	// Le tag pour SearchResultDone est 101 (0x65), pour les autres opérations c'est différent.
	// Cependant, pour une erreur générale, LDAP utilise souvent le tag correspondant à l'opération.
	// Pour simplifier et être compatible, on utilise le format LDAPMessage standard.

	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 101, nil, "LDAPResponse") // 101 = SearchResultDone
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(resultCode), "resultCode"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errMsg, "diagnosticMessage"))

	// 2. Enveloppe du message (LDAPMessage)
	finalPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	finalPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(messageID), "Message ID"))
	finalPacket.AppendChild(response)

	// 3. Envoi sur la socket
	_, err := conn.Write(finalPacket.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send LDAPError: %v", err)
	}

	logs.Write_Log("WARNING", fmt.Sprintf("LDAP Error sent (Code %d): %s", resultCode, errMsg))
	return nil
}

// Affichage structuré des messages LDAP (uniquement si debug)
func printLDAPMessageDebug(message *ldapstorage.LDAPParsedReceivedMessage, protocol, client string) {
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] ===== LDAP Parsed Message (%s) =====", protocol, client))
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Message ID       : %d", protocol, message.MessageID))
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Operation (type) : %s", protocol, message.ProtocolOp.OpType()))

	if len(message.Controls) > 0 {
		logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Controls (%d):", protocol, len(message.Controls)))
		for i, ctrl := range message.Controls {
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]   • Control #%d", protocol, i+1))
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]     - Type        : %s", protocol, ctrl.ControlType))
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]     - Criticalité : %v", protocol, ctrl.Criticality))
			logs.Write_Log("DEBUG", fmt.Sprintf("[%s]     - Valeur      : % X", protocol, ctrl.ControlValue))
		}
	} else {
		logs.Write_Log("DEBUG", fmt.Sprintf("[%s] Controls : Aucun", protocol))
	}
	logs.Write_Log("DEBUG", fmt.Sprintf("[%s] ===============================", protocol))
}

// Lecture binaire d’un paquet LDAP complet
func readLDAPPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("invalid LDAP message: expected SEQUENCE (0x30), got 0x%x", header[0])
	}

	length := int(header[1])
	var lenBytes []byte

	if length&0x80 != 0 {
		numBytes := length & 0x7F
		if numBytes > 4 {
			return nil, fmt.Errorf("invalid BER length: too many length bytes")
		}
		lenBytes = make([]byte, numBytes)
		if _, err := io.ReadFull(conn, lenBytes); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range lenBytes {
			length = (length << 8) | int(b)
		}
	}

	const maxLDAPMessageSize = 4 * 1024 * 1024 // 4 MiB, évite allocation DoS
	if length < 0 || length > maxLDAPMessageSize {
		return nil, fmt.Errorf("invalid LDAP message length: %d (max %d)", length, maxLDAPMessageSize)
	}

	message := make([]byte, length)
	if _, err := io.ReadFull(conn, message); err != nil {
		return nil, err
	}

	totalLen := 2 + len(lenBytes) + length
	fullPacket := make([]byte, totalLen)
	copy(fullPacket, header)
	copy(fullPacket[2:], lenBytes)
	copy(fullPacket[2+len(lenBytes):], message)
	return fullPacket, nil
}
