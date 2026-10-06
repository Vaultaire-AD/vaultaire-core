package permission

import (
	"testing"

	"vaultaire/core/clienttype"
)

// TestClesNexus : les trois clés du dépôt sont administrables, globales, et
// accordées au superadmin par AllActionKeys.
func TestClesNexus(t *testing.T) {
	all := map[string]bool{}
	for _, k := range AllActionKeys() {
		all[k] = true
	}
	for _, k := range []string{ActionReadNexus, ActionWriteNexus, ActionAdminNexus} {
		if n, ok := IsValidAction(k); !ok || n != k {
			t.Errorf("IsValidAction(%q) = %q, %t", k, n, ok)
		}
		if !IsGlobalOnlyAction(k) {
			t.Errorf("%s doit être globale : un dépôt n'appartient à aucun domaine", k)
		}
		if !all[k] {
			t.Errorf("%s absente de AllActionKeys : vaultaire_all ne la recevrait pas", k)
		}
	}
}

// TestUserRightsDuCatalogueSontDesClesConnues : un service ne peut apprendre
// que des clés qui existent. Une faute de frappe dans le catalogue produirait
// une clé que personne ne peut accorder, donc un service qui refuse tout le
// monde sans que rien ne le signale.
func TestUserRightsDuCatalogueSontDesClesConnues(t *testing.T) {
	for _, d := range clienttype.All() {
		for _, k := range d.UserRights {
			if _, ok := IsValidAction(k); !ok {
				t.Errorf("%s : clé %q inconnue du moteur RBAC", d.Name, k)
			}
			if !IsGlobalOnlyAction(k) {
				t.Errorf("%s : clé %q non globale — un service n'a pas de domaine "+
					"sur lequel l'évaluer", d.Name, k)
			}
		}
	}
}
