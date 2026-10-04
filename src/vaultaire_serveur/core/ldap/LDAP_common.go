package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	ldapparser "vaultaire/core/ldap/LDAP_Parser"
	ldapresponse "vaultaire/core/ldap/LDAP_RESPONSE"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/pagination"
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
//
// Rend aussi l'adresse du proxy qui a relayé la connexion, vide s'il n'y en a
// pas : la ligne d'ouverture du journal porte les deux adresses.
func preparerConnexion(conn net.Conn, protocol string, tlsConfig *tls.Config) (net.Conn, string, error) {
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
		return nil, "", err
	}
	relais := ""
	if c.Relais != nil {
		relais = c.Relais.String()
	}
	if tlsConfig != nil {
		return tls.Server(c, tlsConfig), relais, nil
	}
	return c, relais, nil
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
				logs.Write_Log("TRACE", "ldap: fermeture après refus : "+cerr.Error())
			}
			continue
		}

		go func() {
			defer release()
			session, relais, err := preparerConnexion(conn, protocol, tlsConfig)
			if err != nil {
				if cerr := conn.Close(); cerr != nil {
					logs.Write_Log("TRACE", "ldap: fermeture après refus : "+cerr.Error())
				}
				return
			}
			handleLDAPSession(session, protocol, relais)
		}()
	}
}

// Lecture et traitement d'une session LDAP unique
func handleLDAPSession(c net.Conn, protocol, relais string) {
	// Le journal de la connexion d'abord : tout ce qui suit, panique comprise,
	// s'écrit sous son numéro (TO-DO 145).
	ldapjournal.Ouvrir(c, protocol, relais)
	// Le motif de fermeture, dit par la boucle au moment où elle sort.
	motif := "interrompue"

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
	//
	// Déclaré APRÈS la fermeture ci-dessous dans le code, donc exécuté AVANT
	// elle : la ligne CRITICAL porte encore le numéro de la connexion. Le
	// message en cause se lit juste au-dessus — la ligne de l'opération, écrite
	// en « sans réponse » pendant que la panique remontait.
	defer func() {
		// Les recherches paginées de cette connexion rendent leur mémoire avec
		// elle (point 130) : un cookie ne vaut que sur la connexion qui l'a reçu.
		pagination.OublierConnexion(c)
		ldapsessionmanager.ClearSession(c)
		if err := c.Close(); err != nil {
			ldapjournal.Trace(c, "fermeture de la connexion : %v", err)
		}
		ldapjournal.Fermer(c, motif)
	}()

	defer func() {
		if r := recover(); r != nil {
			motif = "panique"
			ldapjournal.Ecrire(c, "CRITICAL", logs.CodeLDAPListen, fmt.Sprintf(
				"panique traitée sur la session %s : %v\n%s",
				c.RemoteAddr(), r, debug.Stack()))
		}
	}()

	ldapsessionmanager.InitLDAPSession(c)
	clientAddr := c.RemoteAddr().String()

	for {
		// Réarmé avant CHAQUE lecture : le délai est absolu, pas glissant.
		//
		// Une session liée obtient le délai long, une session en cours de bind le
		// délai court — un client réel envoie son bind aussitôt connecté.
		sess, existe := ldapsessionmanager.GetLDAPSession(c)
		if !existe {
			// L'unbind a retiré la session et fermé la connexion (RFC 4511
			// §4.3). Relire ne rendrait qu'une erreur « connexion fermée », que
			// le journal prendrait pour une panne.
			motif = "unbind"
			return
		}
		netguard.ArmReadDeadline(c, sess.IsBound)

		packet, err := readLDAPPacket(c)
		if err != nil {
			var expiration net.Error
			switch {
			case err == io.EOF:
				motif = "par le client"
			case errors.Is(err, net.ErrClosed):
				// La connexion a été fermée de ce côté-ci. Ce n'est pas une
				// panne de lecture, et l'écrire en ERROR enverrait chercher un
				// problème de réseau.
				motif = "par le serveur"
			case errors.As(err, &expiration) && expiration.Timeout():
				// Le délai de lecture de netguard : le client n'a plus rien
				// envoyé. C'est la fin ordinaire d'une connexion gardée ouverte
				// par un pool, pas une erreur.
				motif = "délai d'inactivité"
			default:
				motif = "erreur de lecture"
				ldapjournal.Ecrire(c, "ERROR", logs.CodeLDAPListen,
					"lecture du paquet en échec depuis "+clientAddr+" : "+err.Error())
			}
			return
		}

		if ldapjournal.TraceActive() {
			ldapjournal.Trace(c, "%s", traceDuPaquet(packet))
		}

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
				id := messageIDOf(packet)
				op := ldapjournal.Debut(c, id, fmt.Sprintf("opération %d non gérée", unsupported.Tag))
				if appTag, wants := ldapstorage.ResponseTagFor(unsupported.Tag); wants {
					if sendErr := ldapresponse.SendResult(c, id, appTag,
						ldapstorage.ResultUnwillingToPerform, "",
						"operation not supported by this server"); sendErr != nil {
						ldapjournal.Trace(c, "%v", sendErr)
					}
				}
				ldapjournal.Ecrire(c, "WARNING", logs.CodeNone, fmt.Sprintf(
					"opération %d refusée depuis %s", unsupported.Tag, clientAddr))
				op.Fin()
				continue
			}

			// Trame illisible : le message est peut-être tronqué ou forgé. On ne
			// peut pas en extraire un messageID fiable, donc on ne répond pas et on
			// ferme — poursuivre la lecture d'un flux qu'on ne sait plus découper
			// ne produirait que du bruit.
			motif = "trame illisible"
			ldapjournal.Ecrire(c, "ERROR", logs.CodeLDAPListen,
				"analyse du paquet en échec depuis "+clientAddr+" : "+err.Error())
			return
		}

		traiter(c, message)
	}
}

// traiter exécute une opération, encadrée par sa ligne de journal.
//
// Une fonction à part pour le `defer` : la ligne est écrite quand l'opération
// est finie, y compris si elle panique — la ligne dit alors « sans réponse »,
// juste avant le CRITICAL qui porte la pile. C'est exactement ce que le client
// a vu.
func traiter(c net.Conn, message *ldapstorage.LDAPParsedReceivedMessage) {
	op := ldapjournal.Debut(c, message.MessageID,
		ldapjournal.Decrire(message.ProtocolOp, message.Controls))
	defer op.Fin()
	ldapparser.DispatchLDAPOperation(message, message.MessageID, c)
}

// traceDuPaquet rend la ligne de mise au point d'une trame reçue.
//
// # Ce que cette ligne faisait
//
// Elle vidait le paquet ENTIER en hexadécimal, avant toute analyse. Sur un
// BindRequest simple, ce paquet porte le mot de passe en clair — et, quand le
// second facteur est actif, le code à six chiffres qui lui est accolé (voir la
// convention décrite dans LDAP_Limits.go). Le journal est un fichier : il tourne,
// il part dans les sauvegardes.
//
// `debug: false` est livré depuis le point 99, ce qui limite la portée. Mais on
// active DEBUG exactement quand on diagnostique un problème d'annuaire,
// c'est-à-dire au moment où tous les clients LDAP du parc se lient en boucle.
//
// # Ce qui est gardé
//
// Le vidage reste, pour toutes les autres opérations : c'est lui qui permet de
// comprendre une trame mal découpée, et c'est la raison d'être de cette ligne.
// Seul le bind est masqué.
//
// # Où elle s'écrit maintenant
//
// En TRACE, sous l'identifiant de sa connexion (TO-DO 145). Elle s'écrivait en
// DEBUG, une fois par paquet reçu : c'était la ligne la plus longue du journal,
// et celle qu'on lit le moins — elle ne sert qu'à qui soupçonne le découpage
// des trames. L'adresse du client n'y figure plus : elle est sur la ligne
// d'ouverture de la connexion.
func traceDuPaquet(packet []byte) string {
	if peutEtreUnBind(packet) {
		return fmt.Sprintf("paquet reçu : BindRequest de %d octets, contenu masqué", len(packet))
	}
	return fmt.Sprintf("paquet reçu : % X", packet)
}

// peutEtreUnBind répond à la seule question utile ici, et répond OUI quand elle
// ne sait pas.
//
// Le nom dit l'asymétrie : un paquet qu'on n'arrive pas à découper PEUT être un
// bind, et rien ne permet d'affirmer le contraire sans lire le corps — ce qu'il
// s'agit précisément d'éviter. Masquer à tort ne coûte qu'une ligne de mise au
// point, sur un chemin où l'erreur d'analyse est déjà journalisée avec son motif.
// Se tromper dans l'autre sens coûte un mot de passe.
//
// DecodePacketErr et non DecodePacket : la seconde panique sur une entrée
// forgée, et ce code s'exécute sur des octets venus d'inconnus.
func peutEtreUnBind(packet []byte) bool {
	p, err := ber.DecodePacketErr(packet)
	if err != nil || p == nil || len(p.Children) < 2 {
		return true
	}
	op := p.Children[1]
	return op.ClassType == ber.ClassApplication && op.Tag == ldapstorage.AppBindRequest
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
