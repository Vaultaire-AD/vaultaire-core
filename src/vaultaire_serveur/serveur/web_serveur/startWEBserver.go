package webserveur

import (
	"DUCKY/serveur/global/security"
	"DUCKY/serveur/global/security/keymanagement"
	"DUCKY/serveur/storage"
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
	server_Port := strconv.Itoa(storage.Website_Port)
	fmt.Println("Serveur HTTPS démarré sur https://0.0.0.0:" + server_Port)
	log.Fatal(http.ListenAndServeTLS(":"+server_Port, certFile, privateKeyPath, nil))
}
