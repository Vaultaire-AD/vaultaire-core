package storage

var Host_Type string = "core"
var Host_Version string = "2.1.0"

type Config struct {
	ServerListenPort *string `yaml:"serveurlistenport"`
	Api              struct {
		API_Enable *bool `yaml:"api_enable"`
		API_Port   *int  `yaml:"api_port"`
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
	} `yaml:"ldap"`
	Dns struct {
		Dns_Enable *bool `yaml:"dns_enable"`
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
	} `yaml:"automatisation"`
	Debug struct {
		Debug *bool `yaml:"debug"`
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
var Sh_folder_path string = "/opt/vaultaire/automatisation/"

var API_Enable bool = true
var API_Port int = 6643

var Debug bool = false

var Administrateur_Enable bool = true
var Administrateur_Username string = "admin"
var Administrateur_Password string = "admin123"
var Administrateur_PublicKey string = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCm85Bflch3N5E+zOKapQAn6dipdKgj4oeAorbQV9j4bLUJnFvZ8sfvIGVc0gB5oQEv2Vh1A6lqGNK/CrcgZj5ybNoEwxdbkQyRYkJ6NmtxDs1zLyRUr5GCGtjX44JNNnTDdL+E00Aiw8nFBJRlHkV78ehG62p2DeeVLUydnlnT5ey3KJtmY+Tc0dq5AqWdnAsLbZ/JHw/EuZTeifYJ6wmpxp69oHnsvRxBomH2wSp7CjeYTaBpVFF4KChBSXm/gO4quWQT0JBsDyNmPhZ/QwRJKqujh1B5OX6bbKAl5MOC3OoPXfYkyhilaMku9lK5E6i3wLdP08FQ6Op/Psy7ukTTvMduhqsauxZMMx+x12RAT72LFySZ6RSkLKQXhwkO8pG4laNKFQbDoTULC973AKy0le2Jyb7SnNBL+I+KviMojItYCc6QmQ39TVowy6VQimHiPPs6UPTDt8KROm1SEtPSXj7QvtwJU5hbAG9uFVH/udX7y6BhNPkOgCmrH9s5fh0= root@NTFS"
