package ldap

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	ldaptools "DUCKY/serveur/ldap/LDAP-TOOLS"
	ldapparser "DUCKY/serveur/ldap/LDAP_Parser"
	ldapsessionmanager "DUCKY/serveur/ldap/LDAP_SESSION-Manager"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
)

func HandleLDAPSserveur() {
	const (
		certFile       = "/opt/vaultaire/.ssh/ldaps_server.crt"
		privateKeyPath = "/opt/vaultaire/.ssh/ldaps_server.key"
	)

	// Vérifie et génère les certificats s'ils n'existent pas
	if _, err := os.Stat(certFile); os.IsNotExist(err) || ldaptools.FileEmpty(certFile) || ldaptools.FileEmpty(privateKeyPath) {
		log.Println("📜 Certificat ou clé TLS manquants — génération de certificats auto-signés...")
		err := ldaptools.GenerateSelfSignedCert(certFile, privateKeyPath)
		if err != nil {
			log.Fatalf("Erreur génération certs: %v", err)
		}
	}

	// Charge le certificat
	cert, err := tls.LoadX509KeyPair(certFile, privateKeyPath)
	if err != nil {
		log.Fatalf("Erreur chargement des clés TLS: %s", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(storage.Ldaps_Port), tlsConfig)
	if err != nil {
		log.Fatalf("server: failed to listen on LDAPS port: %s", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	fmt.Println("Server listening on LDAPS port 636...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: failed to accept connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			defer func() {
				ldapsessionmanager.DeleteLDAPSession(c)
				defer func() {
					if err := c.Close(); err != nil {
						// Handle or log the error
						logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
					}
				}()
			}()

			ldapsessionmanager.InitLDAPSession(c)

			for {
				packet, err := readLDAPPacket(c)
				if err != nil {
					if err == io.EOF {
						log.Println("Connection closed by client")
					} else {
						log.Printf("Error reading LDAP packet: %s", err)
					}
					return
				}

				fmt.Printf("Received LDAP packet: % X\n", packet)

				message, err := ldapparser.ParseLDAPMessage(packet)
				if err != nil {
					log.Printf("Error parsing LDAP message: %s", err)
					continue
				}

				fmt.Println("===== LDAP Parsed Message =====")
				fmt.Printf("- Message ID         : %d\n", message.MessageID)
				fmt.Printf("- Operation (type)   : %s\n", message.ProtocolOp.OpType())

				if len(message.Controls) > 0 {
					fmt.Printf("- Controls (%d):\n", len(message.Controls))
					for i, ctrl := range message.Controls {
						fmt.Printf("  • Control #%d\n", i+1)
						fmt.Printf("    - Control Type    : %s\n", ctrl.ControlType)
						fmt.Printf("    - Criticality     : %v\n", ctrl.Criticality)
						fmt.Printf("    - Control Value   : % X\n", ctrl.ControlValue)
					}
				} else {
					fmt.Println("- Controls           : Aucun")
				}
				fmt.Println("===============================")

				ldapparser.DispatchLDAPOperation(message, message.MessageID, c)
			}
		}(conn)
	}
}
