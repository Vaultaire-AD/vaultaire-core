package storage

var Host_Type string = "core"
var Host_Version string = "2.3.0"

type Config struct {
	ServerListenPort *string `yaml:"serveurlistenport"`
	Api              struct {
		API_Enable *bool `yaml:"api_enable"`
		API_Port   *int  `yaml:"api_port"`
		// Débit par source sur /api/command (TO-DO 102).
		API_Limite_Rafale      *int     `yaml:"limite_rafale"`
		API_Limite_Par_Seconde *float64 `yaml:"limite_par_seconde"`
		// Certificat importé (TO-DO 262) : voir Ldaps_TLS_CertFile.
		API_TLS_CertFile *string `yaml:"api_tls_cert_file"`
		API_TLS_KeyFile  *string `yaml:"api_tls_key_file"`
	} `yaml:"api"`
	Path struct {
		SocketPath       *string `yaml:"socketpath"`
		Client_Conf_path *string `yaml:"clientconfpath"`
		LogPath          *string `yaml:"logpath"`

		// ServerCheckOnlineTimerObsolete n'est plus LU, seulement DÉTECTÉ.
		//
		// Le champ est conservé pour qu'une installation qui le porte encore
		// reçoive un avertissement nommant son remplacement. Le retirer de la
		// structure ferait ignorer la ligne en silence : l'exploitant verrait sa
		// valeur dans le fichier, sans effet, et chercherait la panne du côté de
		// la boucle plutôt que du côté de la configuration.
		ServerCheckOnlineTimerObsolete *int `yaml:"servercheckonlinetimer"`
	} `yaml:"file-path"`
	Ldap struct {
		Ldap_Enable  *bool `yaml:"ldap_enable"`
		Ldaps_Enable *bool `yaml:"ldaps_enable"`
		Ldap_Port    *int  `yaml:"ldap_port"`
		Ldaps_Port   *int  `yaml:"ldaps_port"`
		// Noms et adresses que le certificat LDAPS doit couvrir.
		//
		// Les clients Java — Keycloak en tête — ignorent le CommonName depuis
		// JDK 9 et exigent un SAN correspondant. La détection automatique ne
		// peut pas deviner un nom de service DNS ni un alias derrière un
		// répartiteur : ces deux listes servent à les déclarer.
		Ldaps_TLS_DNSNames []string `yaml:"ldaps_tls_dns_names"`
		Ldaps_TLS_IPs      []string `yaml:"ldaps_tls_ip_addresses"`
		// Certificat importé (TO-DO 262) : voir storage.Ldaps_TLS_CertFile.
		Ldaps_TLS_CertFile *string `yaml:"ldaps_tls_cert_file"`
		Ldaps_TLS_KeyFile  *string `yaml:"ldaps_tls_key_file"`
		// Laisse les comptes soumis au second facteur se lier avec leur seul
		// mot de passe. Faux par défaut : voir ldapstorage.MFABypass.
		Ldap_MFA_Bypass *bool `yaml:"mfa_bypass"`
		// Élargit TOUTE recherche `one` à l'arborescence, quel que soit le
		// conteneur. Faux par défaut : voir ldapstorage.OneLevelSubtree.
		Ldap_OneLevel_Subtree *bool `yaml:"onelevel_subtree"`
		// Refuse un bind avec mot de passe hors TLS, donc sur le port 389. Faux
		// par défaut : voir ldapstorage.RequireTLSForBind.
		Ldap_Require_TLS_For_Bind *bool `yaml:"require_tls_for_bind"`
		// Bornes de recherche et de pagination (TO-DO 152).
		//
		// Une TABLE et non une structure, à dessein : une structure ignore en
		// silence une clé qu'elle ne connaît pas, et une borne mal orthographiée
		// se lirait dans le fichier sans rien régler. La table laisse
		// ldapstorage.AppliquerLimites voir toutes les clés écrites, et refuser
		// celles qu'il ne connaît pas.
		Ldap_Limites map[string]int `yaml:"limites"`
	} `yaml:"ldap"`
	Dns struct {
		Dns_Enable *bool `yaml:"dns_enable"`
		// Port UDP du DNS. 53 par défaut ; un conteneur sans privilège écoute
		// au-dessus de 1024 et le Service Kubernetes republie le 53.
		Dns_Port *int `yaml:"dns_port"`
	} `yaml:"dns"`
	Database struct {
		Database_username     *string `yaml:"username"`
		Database_password     *string `yaml:"password"`
		Database_iPDatabase   *string `yaml:"ip_database"`
		Database_portDatabase *string `yaml:"port_database"`
		Database_databaseName *string `yaml:"databaseName"`
	} `yaml:"database"`
	Website struct {
		Website_Enable *bool `yaml:"website_enable"`
		Website_Port   *int  `yaml:"website_port"`
		// Noms et adresses que le certificat du serveur web et de l'API REST
		// doit couvrir.
		//
		// Séparés de ceux du LDAPS : ces services ne sont pas atteints par les
		// mêmes noms. Le LDAPS est joint par un annuaire, souvent par un alias
		// de service ; le portail web est joint par un navigateur, à l'URL que
		// les utilisateurs ont en signet.
		Web_TLS_DNSNames []string `yaml:"web_tls_dns_names"`
		Web_TLS_IPs      []string `yaml:"web_tls_ip_addresses"`
		// Certificat importé (TO-DO 262) : voir storage.Ldaps_TLS_CertFile.
		Web_TLS_CertFile *string `yaml:"web_tls_cert_file"`
		Web_TLS_KeyFile  *string `yaml:"web_tls_key_file"`
		// Relais autorisés à déclarer l'adresse réelle du client, en adresses
		// simples ou en préfixes CIDR.
		//
		// VIDE PAR DÉFAUT : sans entrée, l'en-tête X-Forwarded-For est ignoré et
		// c'est l'adresse du pair TCP qui compte. Croire cet en-tête parce qu'il
		// est présent serait pire que de ne rien limiter — il est écrit par le
		// client, donc une valeur différente à chaque tentative donne un compteur
		// de force brute neuf à chaque coup.
		//
		// À renseigner quand le portail est publié derrière un reverse proxy :
		// sans cela toutes les requêtes portent l'adresse du relais, et le premier
		// balayage venu freine tout le monde.
		Web_Trusted_Proxies []string `yaml:"web_trusted_proxies"`
	} `yaml:"website"`
	Automatisation struct {
		Sh_folder_path *string `yaml:"sh_folder_path"`
		// Répertoire du paquet d'agent copié sur un poste par « -join ».
		Agent_Package_path *string `yaml:"agent_package_path"`
	} `yaml:"automatisation"`
	Debug struct {
		Debug *bool `yaml:"debug"`
		// Détail par sous-système (TO-DO 145) : « ldap: trace », « ducky: off ».
		// Une table pour la même raison que ldap.limites — un sous-système mal
		// orthographié doit se voir, pas s'ignorer. Voir logs.ReglerDetail.
		Detail map[string]string `yaml:"detail"`
	} `yaml:"debug"`
	Administrateur struct {
		Enable    *bool   `yaml:"enable"`
		Username  *string `yaml:"username"`
		Password  *string `yaml:"password"`
		PublicKey *string `yaml:"public_key"`
	} `yaml:"administrateur"`
}

var ServeurLisetenPort string = "6666"

var SocketPath string = "/opt/vaultaire/vaultaire.sock"
var Client_Conf_path = "/opt/vaultaire/"
var LogPath = "/var/log/vaultaire/"

// PrivateKeyPath et PublicKeyPath sont obsolètes - les clés sont maintenant en BDD
// Ces variables restent pour compatibilité avec EnsureLoginClientKeyFiles qui écrit temporairement les fichiers SSH
var PrivateKeyPath string = "/opt/vaultaire/.ssh/private_key.pem"
var PublicKeyPath string = "/opt/vaultaire/.ssh/public_key.pub"
var PrivateKeyforlogintoclient string = "/opt/vaultaire/.ssh/private_key_for_login_client_rsa"
var PublicKeyforlogintoclient string = "/opt/vaultaire/.ssh/private_key_for_login_client_rsa.pub"

// ServerCheckOnlineTimer a été RETIRÉ.
//
// La cadence de vérification des machines en ligne est un réglage
// d'exploitation, pas une propriété d'installation : elle vit maintenant en base
// sous la clé « check_online_minutes », avec son défaut codé dans
// core/reglages. La changer ne demande plus de redémarrer le core — c'est-à-dire
// de couper le parc pour ajuster une période.
//
// Le champ « servercheckonlinetimer » du YAML est ignoré s'il subsiste : voir
// ReadConfigFile, qui le signale une fois au démarrage plutôt que de le lire en
// silence.

var Database_username string = "root"
var Database_password string = "root"
var Database_iPDatabase string = "OPPIDUM"
var Database_portDatabase string = "3306"
var Database_databaseName string = "vaultaire"

var AutoAddClientCommandesList []string

var Ldap_Enable bool = true
var Ldaps_Enable bool = true
var Ldap_Port int = 389
var Ldaps_Port int = 636

// Ldaps_TLS_DNSNames et Ldaps_TLS_IPs complètent les noms détectés sur l'hôte.
// Vides par défaut : la détection suffit tant que les clients joignent le
// serveur par son vrai nom de machine.
var Ldaps_TLS_DNSNames []string
var Ldaps_TLS_IPs []string

// Certificats importés — TO-DO 262.
//
// Chemins d'un certificat (PEM, chaîne complète, serveur en tête) et de sa clé,
// fournis par une autorité extérieure : cert-manager dans Kubernetes, une PKI
// d'entreprise ailleurs. Vides par défaut : le service sert alors son
// certificat auto-signé, gardé en base. Les deux ou aucun. Relus à chaud, voir
// le paquet certimporte.
var Ldaps_TLS_CertFile, Ldaps_TLS_KeyFile string
var Web_TLS_CertFile, Web_TLS_KeyFile string
var API_TLS_CertFile, API_TLS_KeyFile string

var Website_Enable bool = true
var Website_Port int = 443

// Web_TLS_DNSNames et Web_TLS_IPs complètent les noms détectés pour le
// certificat du portail web et de l'API REST. Vides par défaut : la détection
// couvre le cas courant.
var Web_TLS_DNSNames []string
var Web_TLS_IPs []string

// Web_Trusted_Proxies liste les relais autorisés à déclarer l'adresse réelle du
// client dans X-Forwarded-For. Vide par défaut : sans entrée, l'en-tête est
// ignoré et c'est l'adresse du pair TCP qui compte. Recopié dans
// ratelimit.ProxiesDeConfiance au démarrage.
var Web_Trusted_Proxies []string

var Dns_Enable bool = true
var Dns_Port int = 53
var Sh_folder_path string = "/opt/vaultaire/automatisation/"

// Agent_Package_path : le paquet d'agent (binaire et modules PAM/NSS) que
// « vlt create -c … -join » copie sur le poste. Lu seulement : dans l'image
// rootless, il est dans la couche en lecture seule, séparé des répertoires
// où le core écrit (Client_Conf_path).
var Agent_Package_path string = "/opt/vaultaire/vaultaire_client/"

var API_Enable bool = true
var API_Port int = 6643

// API_Limite_Rafale et API_Limite_Par_Seconde bornent le débit de chaque source
// sur l'API de commande, avant toute authentification (TO-DO 102).
//
// Un seau de 100 requêtes qui se remplit de 20 par seconde : un intégrateur qui
// envoie sa rafale d'un coup passe, un flot soutenu est ramené à 20 par
// seconde. Voir core/auth/ratelimit/debit.go.
var (
	API_Limite_Rafale      int     = 100
	API_Limite_Par_Seconde float64 = 20
)

var Debug bool = false

var Administrateur_Enable bool = true
var Administrateur_Username string = "admin"

// VIDE, et non « admin123 » — TO-DO 99.
//
// Le défaut du code était identique à la valeur du fichier livré, et c'est ce
// qui a rendu invisible pendant toute la vie du produit le fait que la section
// « administreur: » n'était jamais lue : un exploitant qui changeait le mot de
// passe dans le fichier démarrait quand même sur celui-ci, sans qu'aucun écart
// ne se voie nulle part.
//
// Vide, l'amorçage s'arrête en le disant. C'est bruyant, et c'est exactement ce
// qu'on veut : un mot de passe de superadmin ne doit jamais venir d'un défaut.
var Administrateur_Password string = ""

// VIDE depuis la 2.3. Le défaut était la clé de démonstration du dépôt, dont
// la partie PRIVÉE est publiée (deployments/configs/demo_admin_key) : toute
// installation qui ne disait rien donnait au superadmin une clé que chacun peut
// télécharger. Les piles de développement la posent explicitement dans leur
// fichier ; voir aussi VerifierValeursLivrees.
var Administrateur_PublicKey string = ""
