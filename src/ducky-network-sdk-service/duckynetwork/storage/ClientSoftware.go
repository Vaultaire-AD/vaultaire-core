package storage

var SoftwarePath = "/etc/vaultaire_client/client_software.yaml"
var Computeur_ID string
var LogicielType string
var IsServeur bool

// Persistent commande la RECONNEXION, rien d'autre.
//
// À ne pas confondre avec IsServeur, qui décrit la MACHINE — serveur membre du
// domaine — et vient de client_software.yaml. Les deux étaient confondus : un
// service, pour qui l'enrôlement écrit isServeur=false, tournait donc en mode
// une-passe et ne se reconnectait jamais après une coupure.
//
// Un service veut Persistent ; un utilitaire à usage unique ne le veut pas.
var Persistent bool
var SessionIntegritykey string

type ClientSoftware struct {
	NewClient struct {
		Computeur_id  string `yaml:"computeur_id"`
		Logiciel_type string `yaml:"logiciel_type"`
		IsServeur     bool   `yaml:"isServeur"`
	} `yaml:"client_software"`
}
