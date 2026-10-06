package yaml

import (
	"os"
	"path/filepath"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
)

// L'identité de la machine, lue en yaml.v3 depuis le TO-DO 93.
//
// client_software.yaml est écrit par le core, mais il arrive qu'on le retouche
// à la main sur un poste. yaml.v2 lisait « isServeur: yes » comme vrai ; v3 ne
// le fait que vers un champ booléen. C'est le cas ici, et ce test le fige : un
// poste dont le fichier porte « yes » ne doit pas changer de nature à la mise à
// jour de l'agent.
func TestLIdentiteSeLitCommeLaEcritLeCore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client_software.yaml")
	contenu := "client_software:\n  computeur_id: PC-01\n  logiciel_type: vaultaire_client\n  isServeur: yes\n"
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := readConfig[storage.ClientSoftware](p)
	if err != nil {
		t.Fatal(err)
	}
	if cs.NewClient.Computeur_id != "PC-01" || cs.NewClient.Logiciel_type != "vaultaire_client" {
		t.Fatalf("identité lue = %+v", cs.NewClient)
	}
	if !cs.NewClient.IsServeur {
		t.Fatal("« isServeur: yes » lu comme faux : la machine changerait de nature à la mise à jour")
	}
}
