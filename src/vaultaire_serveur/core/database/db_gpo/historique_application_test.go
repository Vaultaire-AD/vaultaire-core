package dbgpo

import (
	"strings"
	"testing"
)

// L'historique ne vaut que par ce qu'il ne stocke PAS : une ligne par
// changement, pas une par cycle, et un résumé borné. Ces deux propriétés
// décident de la taille de la table sur un parc, et rien d'autre ne les tient.

func TestLeResumeNeRetientQueLesFautifs(t *testing.T) {
	resume := ResumerModulesFautifs([]ModuleReport{
		{StateKey: "ssh", Result: "applied"},
		{StateKey: "pam", Result: "failed"},
		{StateKey: "dns", Result: "unchanged"},
		{StateKey: "firewall", Result: "skipped"},
	})

	if strings.Contains(resume, "ssh") || strings.Contains(resume, "dns") {
		t.Errorf("un module sain figure dans le résumé : %q", resume)
	}
	if !strings.Contains(resume, "pam") || !strings.Contains(resume, "firewall") {
		t.Errorf("un module fautif manque au résumé : %q", resume)
	}
	if !strings.Contains(resume, "failed") || !strings.Contains(resume, "skipped") {
		t.Errorf("le résumé ne dit pas de quel genre d'ennui il s'agit : %q", resume)
	}
}

// Une machine hors service fait échouer tous ses modules à la fois. Sans borne,
// une seule transition écrirait un champ de plusieurs kilo-octets — répété à
// chaque aller-retour d'une machine instable.
func TestLeResumeEstBorne(t *testing.T) {
	var modules []ModuleReport
	for i := 0; i < MaxModulesEnEchecHistorises*3; i++ {
		modules = append(modules, ModuleReport{StateKey: "module", Result: "failed"})
	}

	resume := ResumerModulesFautifs(modules)
	if !strings.Contains(resume, "et 40 de plus") {
		t.Errorf("le résumé ne dit pas ce qu'il a laissé de côté : %q", resume)
	}
	if n := strings.Count(resume, "(failed)"); n != MaxModulesEnEchecHistorises {
		t.Errorf("%d module(s) retenu(s), attendu %d", n, MaxModulesEnEchecHistorises)
	}
}

// Un module sans clé d'état est nommé par son type : une ligne d'historique qui
// dirait « (failed) » sans dire quoi ne servirait à rien.
func TestUnModuleSansCleEstNommeParSonType(t *testing.T) {
	resume := ResumerModulesFautifs([]ModuleReport{
		{ModuleType: "file_deploy", StateKey: "", Result: "failed"},
	})
	if !strings.Contains(resume, "file_deploy") {
		t.Errorf("résumé = %q, attendu le type du module", resume)
	}
}

// Une application entièrement réussie ne laisse aucun résumé : le champ est
// vide, et la ligne d'historique dit « tout va bien depuis ce jour-là ».
func TestUneApplicationSaineNeResumeRien(t *testing.T) {
	if r := ResumerModulesFautifs([]ModuleReport{
		{StateKey: "ssh", Result: "applied"},
		{StateKey: "dns", Result: "unchanged"},
	}); r != "" {
		t.Errorf("résumé = %q, attendu vide", r)
	}
}

// La rétention est une durée POSITIVE. Zéro ou négatif voudrait dire « tout
// supprimer », ce qu'une purge ne doit jamais faire par accident de réglage.
func TestUneRetentionNulleEstRefusee(t *testing.T) {
	if _, err := PurgerHistoriqueApplication(nil, 0); err == nil {
		t.Error("une rétention nulle a été acceptée")
	}
}
