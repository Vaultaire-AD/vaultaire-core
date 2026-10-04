package action

import (
	"fmt"
	"testing"
)

// Poser ou lever un « deny » exige le droit global (TO-DO 104).
//
// Un refus franchit les domaines : il retire l'action à chaque membre des
// groupes qui portent la permission, y compris ce qu'un autre groupe de ce
// membre lui accorde ailleurs. Un délégué de domaine ne doit ni le poser, ni
// l'écraser.
func TestPoserOuLeverUnRefusExigeLeDroitGlobal(t *testing.T) {
	annuaireSimule(t, map[string][]string{"permission:lecture": {"rennes.fr"}})
	valeurs := map[string]string{"read:get:user": "(0:rennes.fr)", "write:update:user": "deny"}
	ancien := lireValeurActionPermission
	lireValeurActionPermission = func(nom, champ string) (string, error) {
		if v, ok := valeurs[champ]; ok {
			return v, nil
		}
		return "", fmt.Errorf("base indisponible")
	}
	t.Cleanup(func() { lireValeurActionPermission = ancien })

	cas := []struct {
		nom    string
		params Params
		attend []string
	}{
		{"ajout ordinaire : le domaine suffit",
			Params{"permission_name": "lecture", "field": "read:get:user", "op": "-a"}, []string{"rennes.fr"}},
		{"nil ordinaire : le domaine suffit",
			Params{"permission_name": "lecture", "field": "read:get:user", "op": "nil"}, []string{"rennes.fr"}},
		{"POSER un deny",
			Params{"permission_name": "lecture", "field": "read:get:user", "op": "deny"}, []string{"*"}},
		{"LEVER un deny par nil",
			Params{"permission_name": "lecture", "field": "write:update:user", "op": "nil"}, []string{"*"}},
		{"LEVER un deny par un ajout de domaine",
			Params{"permission_name": "lecture", "field": "write:update:user", "op": "add"}, []string{"*"}},
		{"valeur actuelle illisible : dans le doute, global",
			Params{"permission_name": "lecture", "field": "write:delete:user", "op": "all"}, []string{"*"}},
	}
	for _, c := range cas {
		got, err := porteeReglageActionPermission(c.params)
		if err != nil {
			t.Fatalf("%s : %v", c.nom, err)
		}
		if !memeEnsemble(got, c.attend) {
			t.Errorf("%s : portée %v, attendue %v", c.nom, got, c.attend)
		}
	}
}
