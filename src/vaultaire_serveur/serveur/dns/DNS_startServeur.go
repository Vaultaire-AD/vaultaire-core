package dns

import (
	dnsdatabase "DUCKY/serveur/dns/DNS_Database"
	dnsparser "DUCKY/serveur/dns/DNS_Parser"
	dnsstorage "DUCKY/serveur/dns/DNS_Storage"
	"DUCKY/serveur/logs"
	"fmt"
	"log"
	"net"
)

func DNS_StartServeur() {
	addr := net.UDPAddr{
		Port: 53,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Erreur d'écoute UDP : %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	fmt.Println("🚀 En attente de requêtes DNS sur le port 53...")
	dnsdatabase.InitDatabase()
	buf := make([]byte, 512)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Erreur de lecture : %v", err)
			continue
		}

		fmt.Println("📩 Requête reçue de " + string(remoteAddr.IP.String()) + ":" + fmt.Sprint(remoteAddr.Port))

		msg, err := dnsparser.ParseDNSMessage(buf[:n])
		if err != nil {
			log.Printf("Erreur parsing DNS : %v", err)
			continue
		}

		if len(msg.Questions) == 0 {
			log.Printf("❌ Aucune question DNS dans le message.")
			continue
		}

		fqdn := msg.Questions[0].Name
		qType := msg.Questions[0].Type

		result, err := ResolveDNSQuery(fqdn, qType)
		if err != nil {
			log.Printf("❌ Résolution échouée pour %s : %v", fqdn, err)

			// 🔴 Construire et envoyer une réponse DNS d'échec
			failResp, buildErr := dnsparser.BuildErrorDNSResponse(msg, 3 /* NXDOMAIN */)
			if buildErr != nil {
				log.Printf("❌ Échec de construction réponse d’erreur : %v", buildErr)
				continue
			}
			_, err := conn.WriteToUDP(failResp, remoteAddr)
			if err != nil {
				log.Printf("❌ Erreur envoi réponse d’échec : %v", err)
			}
			continue
		}
		var respData []byte
		switch qType {
		case 1, 5, 12: // A ou PTR (réponse simple)
			ipOrName := result.(string)
			respData, err = dnsparser.BuildDNSResponse(msg, ipOrName)
			if err != nil {
				log.Printf("❌ Erreur construction réponse : %v", err)
				continue
			}

		case 15: // MX (réponse multiple)
			mxRecords := result.([]dnsstorage.MXRecord)
			respData, err = dnsparser.BuildDNSResponseMX(msg, mxRecords)
			if err != nil {
				log.Printf("❌ Erreur construction réponse : %v", err)
				continue
			}
		case 2: // NS (réponse multiple)
			nsRecords := result.([]dnsstorage.ZoneRecord)
			respData, err = dnsparser.BuildDNSResponseNS(msg, nsRecords)
			if err != nil {
				log.Printf("❌ Erreur construction réponse : %v", err)
				continue
			}
		case 16: // TXT
			txtRecords := result.([]string)
			respData, err = dnsparser.BuildDNSResponseTXT(msg, txtRecords)
			if err != nil {
				log.Printf("❌ Erreur construction réponse : %v", err)
				continue
			}
		default:
			// autres types non supportés
			failResp, buildErr := dnsparser.BuildErrorDNSResponse(msg, 4 /* NOTIMP */)
			if buildErr != nil {
				log.Printf("❌ Erreur construction réponse d’erreur : %v", buildErr)
				continue
			}
			_, err := conn.WriteToUDP(failResp, remoteAddr)
			if err != nil {
				log.Printf("❌ Erreur envoi réponse d’échec : %v", err)
			}
			continue
		}

		_, err = conn.WriteToUDP(respData, remoteAddr)
		if err != nil {
			log.Printf("❌ Erreur envoi réponse : %v", err)
		}
	}
}

// Entrée principale pour résoudre un nom DNS selon son type
func ResolveDNSQuery(fqdn string, qType uint16) (any, error) {
	db := dnsdatabase.GetDatabase()
	switch qType {
	case 1:
		return dnsdatabase.ResolveFQDNToIP(db, fqdn)
	case 12:
		return dnsdatabase.ResolvePTRQuery(db, fqdn)
	case 15: // MX
		records, err := dnsdatabase.ResolveMXRecords(db, fqdn)
		if err != nil {
			return "", err // NXDOMAIN ou autre
		}
		return records, nil
	case 5:
		return dnsdatabase.ResolveCNAME(db, fqdn)
	case 16:
		return dnsdatabase.ResolveTXTRecords(db, fqdn)
	case 2:
		return dnsdatabase.ResolveNSRecords(db, fqdn)
	case 28:
		return "", fmt.Errorf("❌ Type AAAA non supporté")
	default:
		return "", fmt.Errorf("❌ Type de requête DNS non supporté : %d", qType)
	}
}
