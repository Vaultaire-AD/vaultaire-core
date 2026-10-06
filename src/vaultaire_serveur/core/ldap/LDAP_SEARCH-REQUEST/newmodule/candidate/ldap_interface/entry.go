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

	// Restreinte rend l'entrée telle qu'un appelant a le droit de la LIRE : la
	// même, privée de ce que ses attributs nomment et qu'il ne peut pas voir.
	// `lisible` dit si l'appelant a le droit de lire un domaine.
	//
	// # Le défaut qu'elle ferme — TO-DO 132
	//
	// `Domaines` décide si une entrée SORT. Elle ne dit rien de ce que l'entrée
	// CONTIENT, et un attribut peut nommer d'autres entrées : `memberOf` porte le
	// DN des groupes d'un compte. Un délégué de « enov.local » sans propagation
	// ne recevait pas les groupes de « admin.enov.local » — et lisait leurs noms
	// dans le `memberOf` de chaque compte qui en était membre. Les groupes d'un
	// sous-domaine étaient énumérables par qui n'avait pas le droit de les lire.
	//
	// La règle : un attribut ne nomme que ce que l'appelant pourrait lire comme
	// entrée.
	//
	// # Pourquoi dans l'INTERFACE, et pourquoi l'entrée s'en charge
	//
	// Même raison que pour `Domaines` : le compilateur réclamera une réponse au
	// prochain type d'entrée. Et c'est l'entrée qui sait lesquels de ses
	// attributs désignent autre chose qu'elle-même ; le contrôle d'accès, lui,
	// ne connaît que des domaines. Le résolveur ne voit toujours pas les droits,
	// et `security` ne connaît toujours pas les attributs — la séparation posée
	// par le point 120 tient.
	//
	// Appliquée par security.PorteeDeRecherche.Filtrer, donc AVANT le filtre de
	// la recherche : celui-ci s'évalue sur l'entrée restreinte. Sans cela,
	// `(memberOf=cn=secret,…)` répondrait oui ou non sur un groupe que l'appelant
	// ne peut pas lire, et la fuite serait seulement devenue un oracle.
	//
	// Elle rend une COPIE : l'entrée reçue n'est pas modifiée.
	Restreinte(lisible func(domaine string) bool) LDAPEntry
}
