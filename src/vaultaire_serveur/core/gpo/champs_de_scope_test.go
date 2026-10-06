package gpo

import "testing"

// Propriétaire et groupe n'ont de sens qu'en scope machine.
//
// En scope user, le propriétaire est l'utilisateur cible et l'agent le pose
// lui-même : le champ ne changeait rien et affichait le contraire. C'est ce
// qu'a montré la recette du 24/09 — `root` saisi, dossier créé au nom de
// l'utilisateur.

// modulesDeFichier sont les trois modules partagés entre les deux scopes qui
// portaient ces champs.
var modulesDeFichier = []string{ModuleFileDeploy, ModuleDirectoryManage, ModuleTemplatedFile}

func TestProprietaireEtGroupeDisparaissentEnScopeUser(t *testing.T) {
	for _, typ := range modulesDeFichier {
		schema, ok := SchemaFor(typ)
		if !ok {
			t.Fatalf("module %s absent du catalogue", typ)
		}

		for _, champ := range []string{"owner", "group"} {
			if !aLeChamp(schema.FieldsForScope(ScopeMachine), champ) {
				t.Errorf("%s : %q a disparu du scope machine, où il sert", typ, champ)
			}
			if aLeChamp(schema.FieldsForScope(ScopeUser), champ) {
				t.Errorf("%s : %q est encore proposé en scope user", typ, champ)
			}
		}

		// Le reste du module ne doit pas partir avec eux : c'est le risque d'un
		// filtre trop large.
		for _, champ := range []string{"path", "mode", "state"} {
			if !aLeChamp(schema.FieldsForScope(ScopeUser), champ) {
				t.Errorf("%s : %q a disparu du scope user", typ, champ)
			}
		}
	}
}

// Un scope vide (catalogue consulté hors contexte, outillage) montre tout :
// cacher des champs sans pouvoir dire pourquoi serait pire que les montrer.
func TestUnScopeVideNeFiltreRien(t *testing.T) {
	schema, _ := SchemaFor(ModuleFileDeploy)
	if len(schema.FieldsForScope("")) != len(schema.Fields) {
		t.Error("un scope vide a filtré des champs")
	}
}

// LE test de régression de ce lot.
//
// Les GPO user écrites avant ce retrait portent encore « owner » et « group »
// en base, vides. ValidateModule est rappelée sur les modules VOISINS à chaque
// modification d'une GPO : les refuser rendrait ces politiques immodifiables
// tant que personne n'aurait nettoyé la base à la main.
func TestUneGPOUserAncienneResteModifiable(t *testing.T) {
	m := Module{
		Type: ModuleFileDeploy,
		Params: map[string]string{
			"path":    "/%h/.config/vaultaire.conf",
			"mode":    "0644",
			"state":   "present",
			"content": "exemple",
			"owner":   "root", // résidu d'avant le retrait
			"group":   "root",
		},
	}

	out, err := ValidateModule(ScopeUser, m)
	if err != nil {
		t.Fatalf("une GPO user ancienne est refusée : %v", err)
	}
	for _, champ := range []string{"owner", "group"} {
		if _, present := out[champ]; present {
			t.Errorf("%q recopié dans les paramètres normalisés : la clé survivrait "+
				"indéfiniment à son propre retrait", champ)
		}
	}
	// Et le module reste complet.
	for _, champ := range []string{"path", "mode", "state"} {
		if out[champ] == "" {
			t.Errorf("%q perdu à la normalisation", champ)
		}
	}
}

// Le contrat inverse tient toujours : un paramètre qui n'existe nulle part au
// schéma est refusé. C'est ce qui empêche une faute de frappe de passer pour un
// réglage.
func TestUnParametreVraimentInconnuResteRefuse(t *testing.T) {
	m := Module{
		Type: ModuleFileDeploy,
		Params: map[string]string{
			"path": "/%h/x", "mode": "0644", "state": "present", "content": "x",
			"proprietaire": "root",
		},
	}
	if _, err := ValidateModule(ScopeUser, m); err == nil {
		t.Error("un paramètre inconnu a été accepté")
	}
}

// En scope machine, rien ne change : le champ est lu et normalisé comme avant.
func TestEnScopeMachineLeProprietaireEstConserve(t *testing.T) {
	m := Module{
		Type: ModuleFileDeploy,
		Params: map[string]string{
			"path": "/etc/vaultaire/exemple.conf", "mode": "0644", "content": "exemple",
			"state": "present", "owner": "root", "group": "root",
		},
	}
	out, err := ValidateModule(ScopeMachine, m)
	if err != nil {
		t.Fatalf("module machine refusé : %v", err)
	}
	if out["owner"] != "root" {
		t.Errorf("owner = %q, attendu root", out["owner"])
	}
}

func aLeChamp(champs []FieldSchema, nom string) bool {
	for _, f := range champs {
		if f.Name == nom {
			return true
		}
	}
	return false
}
