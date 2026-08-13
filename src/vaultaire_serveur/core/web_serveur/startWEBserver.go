package webserveur

import (
	"crypto/tls"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"
	"vaultaire/core/global/security"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"
)

// Le gabarit de connexion est analysé au chargement du paquet : une erreur ici
// empêche le démarrage, ce qui est voulu — sans page de connexion, personne
// n'entre. Le chemin passe par CheminGabarit, seule source de vérité.
var templates = template.Must(template.ParseFiles(CheminGabarit("sso_login.html")))

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

	VerifierRessourcesWeb()
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(RepertoireStatiques()))))
	http.HandleFunc("/", LoginPageHandler)
	http.HandleFunc("/login", LoginHandler)
	// Étape du second facteur : atteignable uniquement avec le cookie
	// mfa_pending, donc après un mot de passe valide.
	http.HandleFunc("/login/mfa", MFAPageHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/profil", ProfilHandler)
	http.HandleFunc("/profil/mfa", ProfilMFAHandler)
	http.HandleFunc("/admin", AdminIndexHandler)
	http.HandleFunc("/admin/tree", AdminTreePageHandler)
	http.HandleFunc("/admin/api/ldap-tree", AdminLDAPTreeAPIHandler)
	http.HandleFunc("/admin/api/group-info", AdminGroupInfoAPIHandler)
	http.HandleFunc("/admin/api/search", AdminSearchAPIHandler)
	http.HandleFunc("/admin/users", AdminUsersHandler)
	http.HandleFunc("/admin/groups", AdminGroupsHandler)
	http.HandleFunc("/admin/clients", AdminClientsHandler)
	http.HandleFunc("/admin/permissions", AdminPermissionsHandler)
	http.HandleFunc("/admin/gpo", AdminGPOHandler)
	http.HandleFunc("/admin/gpo/restrictions", AdminGPORestrictionsHandler)
	http.HandleFunc("/admin/gpo/compliance", AdminGPOComplianceHandler)
	// Politique d'authentification : réservée au groupe vaultaire, atteinte
	// depuis le tableau de bord (le bandeau de navigation n'est pas modifié).
	http.HandleFunc("/admin/authpolicy", AdminAuthPolicyHandler)
	http.HandleFunc("/admin/enroll", AdminEnrollHandler)
	http.HandleFunc("/admin/certificates", AdminCertificatesHandler)
	http.HandleFunc("/admin/settings", AdminSettingsHandler)
	http.HandleFunc("/admin/logs", AdminLogsHandler)
	http.HandleFunc("/admin/api/logs", AdminLogsAPIHandler)
	http.HandleFunc("/admin/dns", AdminDNSHandler)
	http.HandleFunc("/admin/cluster", AdminClusterHandler)

	serverPort := strconv.Itoa(storage.Website_Port)
	logs.Write_Log("INFO", "webadmin: HTTPS server started on https://0.0.0.0:"+serverPort)
	listener, err := tls.Listen("tcp", ":"+serverPort, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	// DÉLAIS D'ATTENTE. http.Serve n'en pose aucun : une connexion qui envoie
	// ses en-têtes octet par octet immobilise une goroutine indéfiniment, et
	// quelques centaines suffisent à rendre l'interface d'administration
	// injoignable — précisément quand on en a besoin pour réagir.
	//
	// Les valeurs sont larges à dessein : l'envoi d'une clé publique ou d'une
	// GPO volumineuse doit passer sans être coupé.
	server := &http.Server{
		Handler:           nil, // DefaultServeMux, où les routes ci-dessus sont posées
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.Serve(listener))
}
