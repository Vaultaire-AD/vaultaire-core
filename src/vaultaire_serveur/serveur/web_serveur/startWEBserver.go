package webserveur

import (
	"vaultaire/serveur/global/security"
	"vaultaire/serveur/global/security/keymanagement"
	"vaultaire/serveur/storage"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

var templates = template.Must(template.ParseFiles("./web_packet/sso_WEB_page/templates/sso_login.html"))

func StartWebServer() {
	privateKeyPath, _, err := keymanagement.Generate_Serveur_Key_Pair("web_server")
	if err != nil {
		log.Fatalf("Erreur génération paire de clés API : %v", err)
		return

	}
	certFile, err := security.GenerateSelfSignedCert(privateKeyPath, "web-server_cert")
	if err != nil {
		log.Fatalf("Erreur génération certificat : %v", err)
	}
	fmt.Println("Certificat généré avec succès :", certFile, privateKeyPath)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./web_packet/sso_WEB_page/static"))))
	http.HandleFunc("/", LoginPageHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/profil", ProfilHandler)
	// Route pour l'interface d'administration web (dashboard)
	http.HandleFunc("/admin", AdminIndexHandler)
	http.HandleFunc("/admin/tree", AdminTreePageHandler)
	http.HandleFunc("/admin/api/ldap-tree", AdminLDAPTreeAPIHandler)
	http.HandleFunc("/admin/api/group-info", AdminGroupInfoAPIHandler)
	http.HandleFunc("/admin/api/search", AdminSearchAPIHandler)
	http.HandleFunc("/admin/users", AdminUsersHandler)
	http.HandleFunc("/admin/groups", AdminGroupsHandler)
	http.HandleFunc("/admin/clients", AdminClientsHandler)
	http.HandleFunc("/admin/permissions", AdminPermissionsHandler)
	http.HandleFunc("/admin/dns", AdminDNSHandler)
	server_Port := strconv.Itoa(storage.Website_Port)
	fmt.Println("Serveur HTTPS démarré sur https://0.0.0.0:" + server_Port)
	log.Fatal(http.ListenAndServeTLS(":"+server_Port, certFile, privateKeyPath, nil))
}
