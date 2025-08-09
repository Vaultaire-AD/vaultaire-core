package storage

var SoftwarePath = "/opt/vaultaire_client/.ssh/client_software.yaml"
var Computeur_ID string
var LogicielType string
var IsServeur bool
var SessionIntegritykey string

type ClientSoftware struct {
	NewClient struct {
		Computeur_id  string `yaml:"computeur_id"`
		Logiciel_type string `yaml:"logiciel_type"`
		IsServeur     bool   `yaml:"isServeur"`
	} `yaml:"client_software"`
}
