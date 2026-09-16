package ldap_types

// PartialAttribute représente un attribut LDAP avec ses valeurs
type PartialAttribute struct {
	Type string   // Nom de l'attribut (ex: "uid", "displayName")
	Vals []string // Valeurs de l'attribut
}

// SearchResultEntry représente une entrée LDAP complète pour le client
type SearchResultEntry struct {
	ObjectName string             // DN complet de l'objet
	Attributes []PartialAttribute // Liste des attributs
}
