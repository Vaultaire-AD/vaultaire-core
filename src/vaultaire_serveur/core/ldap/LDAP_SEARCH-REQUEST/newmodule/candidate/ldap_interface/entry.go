package ldapinterface

type LDAPEntry interface {
	DN() string
	GetAttribute(attr string) []string
	GetAttributes(attrs []string, typesOnly bool) map[string][]string
	ObjectClasses() []string

	// Domaines rend les domaines Vaultaire auxquels l'entrée est rattachée, sous
	// la forme employée par le RBAC — « admin.enov.local », et non « dc=admin,… ».
	//
	// # Pourquoi c'est dans l'interface
	//
	// Le contrôle d'accès à la recherche s'évaluait sur le seul baseDN demandé.
	// Or le résolveur charge le domaine ET ses sous-domaines : un compte autorisé
	// sur « enov.local » SANS propagation recevait les entrées de
	// « admin.enov.local ». La distinction avec/sans propagation, qui est toute
	// la raison d'être du mode « sans », n'avait aucun effet sur ce chemin.
	//
	// Filtrer suppose de savoir à quoi est rattachée CHAQUE entrée. Le déduire du
	// DN ne marcherait pas : `ToRootDN` ne garde que les deux derniers labels, si
	// bien qu'une entrée de « admin.enov.local » et une de « enov.local » ont
	// exactement le MÊME DN. Le rattachement est donc la seule chose qui les
	// distingue, et il doit être porté, pas reconstruit.
	//
	// Le mettre dans l'INTERFACE, et non dans une fonction auxiliaire, fait que
	// le compilateur réclamera une réponse au prochain type d'entrée ajouté.
	//
	// # Pourquoi PLUSIEURS domaines
	//
	// Un compte appartient à des groupes qui peuvent vivre dans des domaines
	// différents. Le rattacher à un seul obligerait à en choisir un — et la
	// première version de ce correctif choisissait le domaine DEMANDÉ, ce qui
	// autorisait tout compte par construction : le filtre ne voyait jamais que le
	// domaine qui venait d'être autorisé.
	//
	// Une entrée est rendue si l'un AU MOINS de ses rattachements est autorisé.
	// Une liste vide est ÉCARTÉE, jamais laissée passer : voir
	// security.PorteeDeRecherche.
	Domaines() []string
}
