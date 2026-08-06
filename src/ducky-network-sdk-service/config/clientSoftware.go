package config

import (
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// ClientSoftware est l'identité du programme, telle que le core la lui a
// attribuée à l'enrôlement.
//
// Même forme que le client_software.yaml de vaultaire_client, délibérément :
// c'est le même objet, et deux structures divergentes pour la même chose
// finiraient par ne plus se lire l'une l'autre.
//
//	client_software:
//	  computeur_id: aBcDeF123456-06-08-2026
//	  logiciel_type: vaultaire_proxy
//	  isServeur: false
type ClientSoftware struct {
	NewClient struct {
		Computeur_id  string `yaml:"computeur_id"`
		Logiciel_type string `yaml:"logiciel_type"`
		IsServeur     bool   `yaml:"isServeur"`
	} `yaml:"client_software"`
}

// ClientSoftwarePath rend le chemin du fichier d'identité.
//
// Il vit à côté des clés, dans KeyPath, et non près de la configuration : les
// deux vont ensemble. Une identité sans sa clé privée est inutilisable, et les
// séparer permettrait d'en sauvegarder une sans l'autre.
func ClientSoftwarePath() string {
	return filepath.Join(storage.KeyPath, "client_software.yaml")
}

// LoadClientSoftware lit l'identité et renseigne les variables globales.
//
// Retourne false si le fichier n'existe pas : ce n'est pas une erreur, c'est
// l'état normal AVANT le premier enrôlement.
func LoadClientSoftware() (bool, error) {
	path := ClientSoftwarePath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lecture de %s : %w", path, err)
	}

	var cs ClientSoftware
	if err := yaml.Unmarshal(data, &cs); err != nil {
		return false, fmt.Errorf("identité %s illisible : %w", path, err)
	}
	if cs.NewClient.Computeur_id == "" {
		return false, fmt.Errorf("identité %s sans computeur_id", path)
	}

	storage.Computeur_ID = cs.NewClient.Computeur_id
	storage.LogicielType = cs.NewClient.Logiciel_type
	storage.IsServeur = cs.NewClient.IsServeur
	return true, nil
}

// SaveClientSoftware écrit l'identité reçue du core.
//
// Appelée par l'enrôlement, une seule fois. Le fichier est en 0600 : il ne
// contient pas de secret, mais il désigne l'identité du service, et le laisser
// modifiable par un autre compte permettrait de la lui faire changer.
func SaveClientSoftware(computeurID, logicielType string, isServeur bool) error {
	var cs ClientSoftware
	cs.NewClient.Computeur_id = computeurID
	cs.NewClient.Logiciel_type = logicielType
	cs.NewClient.IsServeur = isServeur

	data, err := yaml.Marshal(&cs)
	if err != nil {
		return fmt.Errorf("sérialisation de l'identité : %w", err)
	}
	if err := os.MkdirAll(storage.KeyPath, 0700); err != nil {
		return fmt.Errorf("création de %s : %w", storage.KeyPath, err)
	}
	path := ClientSoftwarePath()
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("écriture de %s : %w", path, err)
	}

	storage.Computeur_ID = computeurID
	storage.LogicielType = logicielType
	storage.IsServeur = isServeur
	logs.Write_log("INFO", "identité enregistrée dans "+path+" : "+computeurID)
	return nil
}
