package ldap

import (
	ldapparser "DUCKY/serveur/ldap/LDAP_Parser"
	ldapsessionmanager "DUCKY/serveur/ldap/LDAP_SESSION-Manager"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

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
		lenBytes = make([]byte, numBytes)
		if _, err := io.ReadFull(conn, lenBytes); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range lenBytes {
			length = (length << 8) | int(b)
		}
	}

	message := make([]byte, length)
	if _, err := io.ReadFull(conn, message); err != nil {
		return nil, err
	}

	// fullPacket := append(header, lenBytes...)
	// fullPacket = append(fullPacket, message...)
	// totalLen := 2 + len(lenBytes) + length
	totalLen := 2 + len(lenBytes) + length
	fullPacket := make([]byte, totalLen)
	copy(fullPacket, header)
	copy(fullPacket[2:], lenBytes)
	copy(fullPacket[2+len(lenBytes):], message)
	return fullPacket, nil
}

func HandleLDAPserveur() {
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(storage.Ldap_Port))
	if err != nil {
		log.Fatalf("server: failed to listen: %s", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()
	fmt.Println("Server listening on LDAP port 389...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: failed to accept connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			defer func() {
				ldapsessionmanager.ClearSession(c)
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

				// DEBUG : affichage brut
				fmt.Printf("Received LDAP packet: % X\n", packet)

				// PARSING
				message, err := ldapparser.ParseLDAPMessage(packet)
				if err != nil {
					log.Printf("Error parsing LDAP message: %s", err)
					continue
				}

				// DEBUG : affichage structuré
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
				// TO DO : switch traitement selon le type d’opération
			}
		}(conn)
	}
}
