package dns

import (
	dnsdatabase "vaultaire/serveur/dns/DNS_Database"
	dnsparser "vaultaire/serveur/dns/DNS_Parser"
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"vaultaire/serveur/logs"
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

	logs.Write_Log("INFO", "dns: waiting for DNS requests on port 53")
	dnsdatabase.InitDatabase()
	buf := make([]byte, 512)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeNetConnection, "dns: read error: "+err.Error())
			continue
		}

		logs.Write_Log("DEBUG", fmt.Sprintf("dns: request received from %s:%d", remoteAddr.IP.String(), remoteAddr.Port))

		msg, err := dnsparser.ParseDNSMessage(buf[:n])
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeNetParse, "dns: parsing error: "+err.Error())
			continue
		}

		if len(msg.Questions) == 0 {
			logs.Write_LogCode("WARNING", logs.CodeNetParse, "dns: no DNS question in message")
			continue
		}

		fqdn := msg.Questions[0].Name
		qType := msg.Questions[0].Type

		result, err := ResolveDNSQuery(fqdn, qType)
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeNetMessage, fmt.Sprintf("dns: resolution failed for %s: %v", fqdn, err))

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
				logs.Write_LogCode("ERROR", logs.CodeNetBuild, "dns: failed to build response: "+err.Error())
				continue
			}

		case 15: // MX (réponse multiple)
			mxRecords := result.([]dnsstorage.MXRecord)
			respData, err = dnsparser.BuildDNSResponseMX(msg, mxRecords)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeNetBuild, "dns: failed to build MX response: "+err.Error())
				continue
			}
		case 2: // NS (réponse multiple)
			nsRecords := result.([]dnsstorage.ZoneRecord)
			respData, err = dnsparser.BuildDNSResponseNS(msg, nsRecords)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeNetBuild, "dns: failed to build NS response: "+err.Error())
				continue
			}
		case 16: // TXT
			txtRecords := result.([]string)
			respData, err = dnsparser.BuildDNSResponseTXT(msg, txtRecords)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeNetBuild, "dns: failed to build TXT response: "+err.Error())
				continue
			}
		default:
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
			logs.Write_LogCode("ERROR", logs.CodeNetSend, "dns: failed to send response: "+err.Error())
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
		return "", fmt.Errorf("dns: AAAA type not supported")
	default:
		return "", fmt.Errorf("dns: unsupported DNS query type: %d", qType)
	}
}
