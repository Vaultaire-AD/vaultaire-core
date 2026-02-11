package webserveur

import (
	dnsdatabase "vaultaire/serveur/dns/DNS_Database"
	dnsstorage "vaultaire/serveur/dns/DNS_Storage"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"net/http"
	"strconv"
	"strings"
)

// AdminDNSHandler serves the DNS management page when Dns_Enable is true.
// Access: web_admin + write:dns (same as command dns).
func AdminDNSHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "write:dns") {
		return
	}
	if !storage.Dns_Enable {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	db := dnsdatabase.GetDatabase()
	if db == nil {
		data := struct {
			Message   string
			Username  string
			DnsEnable bool
			Section   string
		}{Message: "DNS non disponible (base de données non initialisée).", Username: username, DnsEnable: true, Section: "dns"}
		_ = executeAdminPage(w, "admin_dns.html", data)
		return
	}

	data := struct {
		Zones     []dnsstorage.Zone
		Records   []dnsstorage.ZoneRecord
		Zone      string
		Message   string
		Username  string
		DnsEnable bool
		Section   string
	}{Username: username, DnsEnable: true, Section: "dns"}
	data.Zone = r.URL.Query().Get("zone")

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		switch action {
		case "create_zone":
			zone := strings.ToLower(strings.TrimSpace(r.FormValue("zone_name")))
			if zone == "" {
				data.Message = "Nom de zone requis."
			} else if err := dnsdatabase.CreateZoneTable(db, zone); err != nil {
				data.Message = "Erreur : " + err.Error()
				logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin dns: create zone failed: "+err.Error())
			} else {
				data.Message = "Zone créée."
				data.Zone = zone
			}
		case "add_record":
			zone := r.FormValue("zone")
			name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
			recordType := strings.ToUpper(strings.TrimSpace(r.FormValue("record_type")))
			recordData := r.FormValue("data")
			ttlStr := r.FormValue("ttl")
			ttl, _ := strconv.Atoi(ttlStr)
			if ttl <= 0 {
				ttl = 300
			}
			prioStr := r.FormValue("priority")
			prio, _ := strconv.Atoi(prioStr)
			if zone == "" || name == "" || recordType == "" || recordData == "" {
				data.Message = "Zone, nom, type et data requis."
			} else {
				fqdn := zone
				if name != "@" {
					fqdn = name + "." + zone
				}
				if err := dnsdatabase.AddDNSRecordSmart(db, fqdn, recordType, ttl, recordData, prio); err != nil {
					data.Message = "Erreur : " + err.Error()
				} else {
					data.Message = "Enregistrement ajouté."
					data.Zone = zone
				}
			}
		case "delete_record":
			zone := r.FormValue("zone")
			name := r.FormValue("record_name")
			recordType := r.FormValue("record_type")
			if zone != "" && name != "" && recordType != "" {
				fqdn := zone
				if name != "@" {
					fqdn = name + "." + zone
				}
				if err := dnsdatabase.DeleteDNSRecord(db, fqdn, recordType); err != nil {
					data.Message = "Erreur : " + err.Error()
				} else {
					data.Message = "Enregistrement supprimé."
					data.Zone = zone
				}
			}
		}
	}

	zones, err := dnsdatabase.GetAllDNSZones(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin dns: list zones failed: "+err.Error())
		data.Message = "Erreur chargement zones."
	} else {
		data.Zones = zones
	}
	if data.Zone != "" {
		records, err := dnsdatabase.GetZoneRecords(db, data.Zone)
		if err != nil {
			data.Message = "Erreur chargement enregistrements."
		} else {
			data.Records = records
		}
	}

	if err := executeAdminPage(w, "admin_dns.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
