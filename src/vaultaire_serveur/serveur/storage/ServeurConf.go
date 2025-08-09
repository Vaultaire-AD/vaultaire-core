package storage

type Config struct {
	ServerListenPort string `yaml:"serveurlistenport"`

	Path struct {
		SocketPath                 string `yaml:"socketpath"`
		PrivateKeyPath             string `yaml:"privatekeypath"`
		PublicKeyPath              string `yaml:"publickeypath"`
		PrivateKeyforlogintoclient string `yaml:"privatekeyforlogintoclient"`
		PublicKeyforlogintoclient  string `yaml:"publickeyforlogintoclient"`
		Client_Conf_path           string `yaml:"clientconfpath"`
		LogPath                    string `yaml:"logpath"`
		ServerCheckOnlineTimer     int    `yaml:"servercheckonlinetimer"`
	} `yaml:"file-path"`
	Ldap struct {
		Ldap_Enable  bool `yaml:"ldap_enable"`
		Ldaps_Enable bool `yaml:"ldaps_enable"`
		Ldap_Debug   bool `yaml:"ldap_debug"`
		Ldap_Port    int  `yaml:"ldap_port"`
		Ldaps_Port   int  `yaml:"ldaps_port"`
	} `yaml:"ldap"`
	Dns struct {
		Dns_Enable bool `yaml:"dns_enable"`
	} `yaml:"dns"`
	Database struct {
		Database_username     string `yaml:"username"`
		Database_password     string `yaml:"password"`
		Database_iPDatabase   string `yaml:"ip_database"`
		Database_portDatabase string `yaml:"port_database"`
		Database_databaseName string `yaml:"databaseName"`
	} `yaml:"database"`
	Website struct {
		Website_Enable bool `yaml:"website_enable"`
		Website_Port   int  `yaml:"website_port"`
	} `yaml:"website"`
	Automatisation struct {
		Sh_folder_path string `yaml:"sh_folder_path"`
	} `yaml:"automatisation"`
}

var ServeurLisetenPort string = "6666"

var SocketPath string = "/opt/vaultaire/vaultaire.sock"
var Client_Conf_path = "/opt/vaultaire/"
var LogPath = "/var/log/vaultaire/"
var PrivateKeyPath string = "/opt/vaultaire/.ssh/private_key.pem"
var PublicKeyPath string = "/opt/vaultaire/.ssh/public_key.pub"
var PrivateKeyforlogintoclient string = "/opt/vaultaire/.ssh/private_key_for_login_client_rsa"
var PublicKeyforlogintoclient string = "/opt/vaultaire/.ssh/private_key_for_login_client_rsa.pub"
var ServerCheckOnlineTimer int = 5

var Database_username string = "root"
var Database_password string = "root"
var Database_iPDatabase string = "OPPIDUM"
var Database_portDatabase string = "3306"
var Database_databaseName string = "vaultaire"

var AutoAddClientCommandesList []string

var Ldap_Debug bool = false
var Ldap_Enable bool = true
var Ldaps_Enable bool = true
var Ldap_Port int = 389
var Ldaps_Port int = 636

var Website_Enable bool = true
var Website_Port int = 443

var Dns_Enable bool = true
var Sh_folder_path string = "/opt/vaultaire/automatisation/"
