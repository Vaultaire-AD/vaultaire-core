package dbauthpolicy

// DisabledPolicy est la politique par défaut : aucune expiration.
//
// C'est aussi la valeur de repli en cas d'échec de lecture — voir
// GetPasswordPolicy.
//
// # L'expiration se replie ouverte, la longueur minimale NON
//
// Les conséquences ne sont pas symétriques, et c'est ce qui décide. Un repli
// fermé sur l'expiration verrouillerait tout l'annuaire sur une erreur de
// lecture : la totalité des comptes marqués expirés, sur les trois chemins à la
// fois. Un repli ouvert sur la longueur minimale, lui, ne casse rien — il laisse
// seulement CRÉER un mot de passe faible pendant la panne, et ce mot de passe
// reste faible une fois la panne finie.
//
// La longueur minimale garde donc sa valeur par défaut même quand la politique
// est illisible. Refuser une création parce que la base ne répond pas est sans
// gravité : on réessaie. Accepter « 1234 » pour la même raison ne se rattrape
// pas.
var DisabledPolicy = PasswordPolicySettings{
	MaxAgeDays: 0,
	WarnDays:   defaultWarnDays,
	MinLength:  MinLengthDefaut,
}
