package dbschema

import (
	"os"
	"strings"
	"testing"
)

// Les deux chemins de création de `cluster_nodes.owner_client_id`.
//
// # Pourquoi ce test existe
//
// La colonne est définie DEUX FOIS : dans le texte du `CREATE TABLE`, que prend
// une base neuve, et dans `DefinitionProprietaire`, que prend une base
// existante par `ALTER TABLE`.
//
// Les faire diverger donnerait deux schémas selon l'ÂGE de l'installation. Le
// défaut serait silencieux au démarrage et se manifesterait sur une requête qui
// marche ici et pas là — la pire forme, parce qu'on cherche alors du côté des
// données plutôt que du schéma.
//
// La duplication est assumée : fabriquer le CREATE TABLE par concaténation pour
// éviter de répéter une ligne rendrait tout le fichier de schéma illisible, et ce
// fichier est ce qu'on lit pour comprendre la base. Un test coûte moins cher.

// lireSchema rend le texte du fichier de création des tables.
func lireSchema(t *testing.T) string {
	t.Helper()
	contenu, err := os.ReadFile("create_data_base.go")
	if err != nil {
		t.Fatalf("lecture de create_data_base.go : %v", err)
	}
	return string(contenu)
}

// TestLaColonneEstDefinieALIdentiqueDesDeuxCotes.
//
// LE test de ce fichier. Une base neuve et une base complétée doivent porter la
// MÊME colonne — même type, même contrainte, même valeur par défaut.
func TestLaColonneEstDefinieALIdentiqueDesDeuxCotes(t *testing.T) {
	schema := lireSchema(t)

	attendu := ColonneProprietaire + " " + DefinitionProprietaire
	if !strings.Contains(schema, attendu) {
		t.Errorf("le CREATE TABLE ne contient pas %q.\n"+
			"  Une base NEUVE prend le texte du CREATE, une base EXISTANTE prend\n"+
			"  DefinitionProprietaire. Les faire diverger donnerait deux schémas\n"+
			"  selon l'âge de l'installation.", attendu)
	}
}

// TestLIndexPorteLeMemeNomDesDeuxCotes.
//
// Un nom différent ferait poser DEUX index uniques sur la même colonne : la base
// neuve aurait le sien, et EnsureUniqueIndex, ne trouvant pas le nom qu'il
// cherche, en ajouterait un second. Sans erreur, et sans que rien ne le dise.
func TestLIndexPorteLeMemeNomDesDeuxCotes(t *testing.T) {
	schema := lireSchema(t)

	if !strings.Contains(schema, "UNIQUE KEY "+IndexProprietaire+" ("+ColonneProprietaire+")") {
		t.Errorf("le CREATE TABLE ne déclare pas l'index %q sur %q : "+
			"une base neuve et une base complétée n'auraient pas le même index",
			IndexProprietaire, ColonneProprietaire)
	}
}

// TestLaTableEstBienCelleDuSchema : garde le nom de table synchronisé.
func TestLaTableEstBienCelleDuSchema(t *testing.T) {
	schema := lireSchema(t)

	if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS "+TableNoeuds+" (") {
		t.Errorf("aucun CREATE TABLE pour %q : le complément de schéma viserait "+
			"une table qui n'est pas créée ici", TableNoeuds)
	}
}

// TestLesIdentifiantsPassentLeMotifDeSchematools.
//
// schematools refuse les identifiants qui ne sont pas en minuscules et
// soulignés — c'est ce qui rend sûre une concaténation que MySQL n'accepte pas
// en paramètre lié. Un nom qui ne passe pas ferait échouer le complément de
// schéma AU DÉMARRAGE, et le core s'arrêterait.
func TestLesIdentifiantsPassentLeMotifDeSchematools(t *testing.T) {
	for _, id := range []string{TableNoeuds, ColonneProprietaire, IndexProprietaire} {
		if id == "" {
			t.Error("identifiant vide")
			continue
		}
		if strings.ToLower(id) != id {
			t.Errorf("%q contient des majuscules : refusé par schematools", id)
		}
		if strings.ContainsAny(id, " -.`\"';()") {
			t.Errorf("%q contient un caractère refusé par schematools", id)
		}
		if len(id) > 64 {
			t.Errorf("%q dépasse 64 caractères", id)
		}
	}
}
