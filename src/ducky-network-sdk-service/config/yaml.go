package config

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// enYAML sérialise avec une indentation de DEUX espaces.
//
// yaml.v3 indente de quatre par défaut, yaml.v2 de deux. Le passage à v3
// (TO-DO 93) ne doit pas changer la forme des fichiers que le parc réécrit :
// un diff de configuration qui ne montre que de l'indentation cache la ligne
// qui a vraiment changé. Deux espaces, c'est aussi ce qu'écrit le core pour
// client_software.yaml (new_client, SetIndent(2)).
func enYAML(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
