package dbschema

// legacyColumnsSuperadmin réplique la table de routage de dbpermission.
//
// Dupliquée plutôt qu'importée : db_permission importe core/database, l'inverse
// créerait un cycle. Elle est figée — ces cinq colonnes sont un héritage du
// modèle LDAP d'origine et aucune n'a été ajoutée depuis — donc le risque de
// dérive est nul, contrairement à la liste d'actions qui, elle, s'allonge.
var legacyColumnsSuperadmin = map[string]bool{
	"none": true, "web_admin": true, "auth": true, "compare": true, "search": true,
}
