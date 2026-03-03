package webserveur

import (
	"vaultaire/serveur/global/security"
	"vaultaire/serveur/storage"
	duckykey "vaultaire/serveur/ducky-network/key_management"
	"vaultaire/serveur/logs"
	"crypto/tls"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

var templates = template.Must(template.ParseFiles("./web_packet/sso_WEB_page/templates/sso_login.html"))

func StartWebServer() {
	certPEM, keyPEM, err := duckykey.GetCertificatePEMFromDB(duckykey.WebServerCertName)
	if err != nil {
		certPEM, keyPEM, err = security.GenerateSelfSignedCertPEM()
		if err != nil {
			log.Fatalf("Erreur génération certificat : %v", err)
		}
		if errSave := duckykey.SaveCertificateToDB(duckykey.WebServerCertName, "tls_cert", "Certificat TLS serveur web", certPEM, keyPEM); errSave != nil {
			// Certificat déjà en BDD (créé entre-temps) : on utilise celui de la BDD
			certPEM, keyPEM, err = duckykey.GetCertificatePEMFromDB(duckykey.WebServerCertName)
			if err != nil {
				log.Fatalf("Erreur récupération certificat web depuis BDD : %v", err)
			}
		}
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		log.Fatalf("Erreur chargement certificat TLS : %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./web_packet/sso_WEB_page/static"))))
	http.HandleFunc("/", LoginPageHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/profil", ProfilHandler)
	http.HandleFunc("/admin", AdminIndexHandler)
	http.HandleFunc("/admin/tree", AdminTreePageHandler)
	http.HandleFunc("/admin/api/ldap-tree", AdminLDAPTreeAPIHandler)
	http.HandleFunc("/admin/api/group-info", AdminGroupInfoAPIHandler)
	http.HandleFunc("/admin/api/search", AdminSearchAPIHandler)
	http.HandleFunc("/admin/users", AdminUsersHandler)
	http.HandleFunc("/admin/groups", AdminGroupsHandler)
	http.HandleFunc("/admin/clients", AdminClientsHandler)
	http.HandleFunc("/admin/permissions", AdminPermissionsHandler)
	http.HandleFunc("/admin/certificates", AdminCertificatesHandler)
	http.HandleFunc("/admin/logs", AdminLogsHandler)
	http.HandleFunc("/admin/api/logs", AdminLogsAPIHandler)
	http.HandleFunc("/admin/dns", AdminDNSHandler)

	serverPort := strconv.Itoa(storage.Website_Port)
	logs.Write_Log("INFO", "webadmin: HTTPS server started on https://0.0.0.0:"+serverPort)
	listener, err := tls.Listen("tcp", ":"+serverPort, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(listener, nil))
}
